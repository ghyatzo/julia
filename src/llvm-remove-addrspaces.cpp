// This file is a part of Julia. License is MIT: https://julialang.org/license

#include "llvm-version.h"

#include <llvm/IR/Module.h>
#include <llvm/IR/Verifier.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Support/Debug.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <llvm/Transforms/Utils/ValueMapper.h>

#include "passes.h"
#include "llvm-codegen-shared.h"

#define DEBUG_TYPE "remove_addrspaces"

using namespace llvm;

using AddrspaceRemapFunction = std::function<unsigned(unsigned)>;


//
// Helpers
//

class AddrspaceRemoveTypeRemapper : public ValueMapTypeRemapper {
    AddrspaceRemapFunction ASRemapper;

public:
    AddrspaceRemoveTypeRemapper(AddrspaceRemapFunction ASRemapper)
        : ASRemapper(ASRemapper)
    {
    }

    Type *remapType(Type *SrcTy)
    {
        // If we already have an entry for this type, return it.
        Type *DstTy = MappedTypes[SrcTy];
        if (DstTy)
            return DstTy;

        DstTy = SrcTy;
        if (auto Ty = dyn_cast<PointerType>(SrcTy)) {
            DstTy = PointerType::get(Ty->getContext(), ASRemapper(Ty->getAddressSpace()));
        }
        else if (auto Ty = dyn_cast<FunctionType>(SrcTy)) {
            SmallVector<Type *, 4> Params;
            for (unsigned Index = 0; Index < Ty->getNumParams(); ++Index)
                Params.push_back(remapType(Ty->getParamType(Index)));
            DstTy = FunctionType::get(
                    remapType(Ty->getReturnType()), Params, Ty->isVarArg());
        }
        else if (auto Ty = dyn_cast<StructType>(SrcTy)) {
            if (Ty->isLiteral()) {
                // Since a literal type has to have the body when it is created,
                // we need to remap the element types first. This is safe only
                // for literal types (i.e., no self-reference) and thus treated
                // separately.
                assert(!Ty->hasName()); // literal type has no name.
                SmallVector<Type *, 4> NewElTys;
                NewElTys.reserve(Ty->getNumElements());
                for (auto E: Ty->elements())
                    NewElTys.push_back(remapType(E));
                DstTy = StructType::get(Ty->getContext(), NewElTys, Ty->isPacked());
            } else if (!Ty->isOpaque()) {
                // If the struct type is not literal and not opaque, it can have
                // self-referential fields (i.e., pointer type of itself as a
                // field).
                StructType *DstTy_ = StructType::create(Ty->getContext());
                if (Ty->hasName()) {
                    auto Name = std::string(Ty->getName());
                    Ty->setName(Name + ".bad");
                    DstTy_->setName(Name);
                }
                // To avoid infinite recursion, shove the placeholder of the DstTy before
                // recursing into the element types:
                MappedTypes[SrcTy] = DstTy_;

                auto Els = Ty->getNumElements();
                SmallVector<Type *, 4> NewElTys(Els);
                for (unsigned i = 0; i < Els; ++i)
                    NewElTys[i] = remapType(Ty->getElementType(i));
                DstTy_->setBody(NewElTys, Ty->isPacked());
                DstTy = DstTy_;
            }
        }
        else if (auto Ty = dyn_cast<ArrayType>(SrcTy))
            DstTy = ArrayType::get(
                    remapType(Ty->getElementType()), Ty->getNumElements());
        else if (auto Ty = dyn_cast<VectorType>(SrcTy))
            DstTy = VectorType::get(remapType(Ty->getElementType()), Ty);

        if (DstTy != SrcTy)
            LLVM_DEBUG(
                    dbgs() << "Remapping type:\n"
                           << "  from " << *SrcTy << "\n"
                           << "  to   " << *DstTy << "\n");

        MappedTypes[SrcTy] = DstTy;
        return DstTy;
    }

private:
    DenseMap<Type *, Type *> MappedTypes;
};


class AddrspaceRemoveValueMaterializer : public ValueMaterializer {
    ValueToValueMapTy &VM;
    RemapFlags Flags;
    ValueMapTypeRemapper *TypeMapper = nullptr;

public:
    AddrspaceRemoveValueMaterializer(
            ValueToValueMapTy &VM,
            RemapFlags Flags = RF_None,
            ValueMapTypeRemapper *TypeMapper = nullptr)
        : VM(VM), Flags(Flags), TypeMapper(TypeMapper)
    {
    }

    Value *materialize(Value *SrcV)
    {
        Value *DstV = nullptr;
        if (auto CE = dyn_cast<ConstantExpr>(SrcV)) {
            Type *Ty = remapType(CE->getType());
            if (CE->getOpcode() == Instruction::AddrSpaceCast) {
                // peek through addrspacecasts if their address spaces match
                // (like RemoveNoopAddrSpaceCasts, but for const exprs)
                Constant *Src = mapConstant(CE->getOperand(0));
                if (Src->getType()->getPointerAddressSpace() ==
                    Ty->getPointerAddressSpace())
                    DstV = Src;
            }
            else {
                // recreate other const exprs with their operands remapped
                SmallVector<Constant *, 4> Ops;
                for (unsigned Index = 0; Index < CE->getNumOperands();
                     ++Index) {
                    Constant *Op = CE->getOperand(Index);
                    Constant *NewOp = mapConstant(Op);
                    Ops.push_back(NewOp ? cast<Constant>(NewOp) : Op);
                }

                if (CE->getOpcode() != Instruction::GetElementPtr)
                    DstV = CE->getWithOperands(Ops, Ty);
            }
        }

        if (DstV)
            LLVM_DEBUG(
                    dbgs() << "Materializing value:\n"
                           << "  from " << *SrcV << "\n"
                           << "  to   " << *DstV << "\n");
        return DstV;
    }

private:
    Type *remapType(Type *SrcTy)
    {
        if (TypeMapper)
            return TypeMapper->remapType(SrcTy);
        else
            return SrcTy;
    }

    Value *mapValue(Value *V)
    {
        return MapValue(V, VM, Flags, TypeMapper, this);
    }

    Constant *mapConstant(Constant *V)
    {
        return MapValue(V, VM, Flags, TypeMapper, this);
    }
};

bool RemoveNoopAddrSpaceCasts(Function *F)
{
    bool Changed = false;

    SmallVector<AddrSpaceCastInst *, 4> NoopCasts;
    for (Instruction &I : instructions(F)) {
        if (auto *ASC = dyn_cast<AddrSpaceCastInst>(&I)) {
            if (ASC->getSrcAddressSpace() == ASC->getDestAddressSpace()) {
                LLVM_DEBUG(
                        dbgs() << "Removing noop address space cast:\n"
                               << I << "\n");
                if (ASC->getType() == ASC->getOperand(0)->getType()) {
                    ASC->replaceAllUsesWith(ASC->getOperand(0));
                } else {
                    // uncanonicalized addrspacecast; just use the value
                    ASC->replaceAllUsesWith(ASC->getOperand(0));
                }
                NoopCasts.push_back(ASC);
            }
        }
    }
    for (auto &I : NoopCasts)
        I->eraseFromParent();

    return Changed;
}

static void copyComdat(GlobalObject *Dst, const GlobalObject *Src)
{
    const Comdat *SC = Src->getComdat();
    if (!SC)
        return;
    Comdat *DC = Dst->getParent()->getOrInsertComdat(SC->getName());
    DC->setSelectionKind(SC->getSelectionKind());
    Dst->setComdat(DC);
}


//
// Actual pass
//

unsigned removeAllAddrspaces(unsigned AS)
{
    return AddressSpace::Generic;
}

bool removeAddrspaces(Module &M, AddrspaceRemapFunction ASRemapper)
{
    ValueToValueMapTy VMap;
    AddrspaceRemoveTypeRemapper TypeRemapper(ASRemapper);
    AddrspaceRemoveValueMaterializer Materializer(
            VMap, RF_None, &TypeRemapper);

    // Loop over all of the global variables, creating versions without address
    // spaces. We only add the new globals to the VMap, attributes and
    // initializers come later.
    SmallVector<GlobalVariable *, 4> Globals;
    for (auto &GV : M.globals())
        Globals.push_back(&GV);
    for (auto &GV : Globals) {
        std::string Name;
        if (GV->hasName()) {
            Name = std::string(GV->getName());
            GV->setName(Name + ".bad");
        }
        else
            Name = "";

        GlobalVariable *NGV = new GlobalVariable(
                M,
                TypeRemapper.remapType(GV->getValueType()),
                GV->isConstant(),
                GV->getLinkage(),
                (Constant *)nullptr,
                Name,
                (GlobalVariable *)nullptr,
                GV->getThreadLocalMode(),
                cast<PointerType>(TypeRemapper.remapType(GV->getType()))->getAddressSpace());
        NGV->copyAttributesFrom(GV);
        VMap[GV] = NGV;
    }

    // Loop over the aliases in the module.
    SmallVector<GlobalAlias *, 4> Aliases;
    for (auto &GA : M.aliases())
        Aliases.push_back(&GA);
    for (auto &GA : Aliases) {
        std::string Name;
        if (GA->hasName()) {
            Name = std::string(GA->getName());
            GA->setName(Name + ".bad");
        }
        else
            Name = "";

        auto *NGA = GlobalAlias::create(
                TypeRemapper.remapType(GA->getValueType()),
                cast<PointerType>(TypeRemapper.remapType(GA->getType()))->getAddressSpace(),
                GA->getLinkage(),
                Name,
                &M);
        NGA->copyAttributesFrom(GA);
        VMap[GA] = NGA;
    }

    // Loop over the functions in the module, creating new ones as before.
    SmallVector<Function *, 4> Functions;
    for (Function &F : M)
        Functions.push_back(&F);
    for (Function *F : Functions) {
        std::string Name;
        if (F->hasName()) {
            Name = std::string(F->getName());
            F->setName(Name + ".bad");
        }
        else
            Name = "";

        FunctionType *FTy = cast<FunctionType>(F->getValueType());
        SmallVector<Type *, 3> Tys;
        for (Type *Ty : FTy->params())
            Tys.push_back(TypeRemapper.remapType(Ty));
        FunctionType *NFTy = FunctionType::get(
                TypeRemapper.remapType(FTy->getReturnType()),
                Tys,
                FTy->isVarArg());

        Function *NF = Function::Create(
                NFTy, F->getLinkage(), F->getAddressSpace(), Name, &M);
        // no need to copy attributes here, that's done by CloneFunctionInto
        VMap[F] = NF;
    }

    // Now that all of the things that global variable initializer can refer to
    // have been created, loop through and copy the global variable referrers
    // over...  We also set the attributes on the globals now.
    for (GlobalVariable *GV : Globals) {
        if (GV->isDeclaration())
            continue;

        GlobalVariable *NGV = cast<GlobalVariable>(VMap[GV]);
        if (GV->hasInitializer())
            NGV->setInitializer(MapValue(GV->getInitializer(), VMap, RF_None, &TypeRemapper, &Materializer));

        SmallVector<std::pair<unsigned, MDNode *>, 1> MDs;
        GV->getAllMetadata(MDs);
        for (auto MD : MDs)
            NGV->addMetadata(
                    MD.first,
                    *MapMetadata(MD.second, VMap));

        copyComdat(NGV, GV);

        GV->setInitializer(nullptr);
    }

    // Similarly, copy over and rewrite function bodies
    for (Function *F : Functions) {
        Function *NF = cast<Function>(VMap[F]);
        LLVM_DEBUG(dbgs() << "Processing function " << NF->getName() << "\n");
        // we also need this to run for declarations, or attributes won't be copied

        Function::arg_iterator DestI = NF->arg_begin();
        for (Function::const_arg_iterator I = F->arg_begin(); I != F->arg_end();
             ++I) {
            DestI->setName(I->getName());
            VMap[&*I] = &*DestI++;
        }

        SmallVector<ReturnInst *, 8> Returns; // Ignore returns cloned.
        CloneFunctionInto(
                NF,
                F,
                VMap,
                CloneFunctionChangeType::GlobalChanges,
                Returns,
                "",
                nullptr,
                &TypeRemapper,
                &Materializer);

        // Update function attributes that contain types
        AttributeList Attrs = F->getAttributes();
        LLVMContext &C = F->getContext();
        for (unsigned i = 0; i < Attrs.getNumAttrSets(); ++i) {
            for (Attribute::AttrKind TypedAttr :
                 {Attribute::ByVal, Attribute::StructRet, Attribute::ByRef}) {
                auto Attr = Attrs.getAttributeAtIndex(i, TypedAttr);
                if (Type *Ty = Attr.getValueAsType()) {
                    Attrs = Attrs.replaceAttributeTypeAtIndex(
                        C, i, TypedAttr, TypeRemapper.remapType(Ty));
                    break;
                }
            }
        }
        NF->setAttributes(Attrs);

        copyComdat(NF, F);

        RemoveNoopAddrSpaceCasts(NF);
        F->deleteBody();
    }

    // And aliases
    for (GlobalAlias *GA : Aliases) {
        GlobalAlias *NGA = cast<GlobalAlias>(VMap[GA]);
        if (const Constant *C = GA->getAliasee())
            NGA->setAliasee(MapValue(C, VMap, RF_None, &TypeRemapper, &Materializer));

        GA->setAliasee(nullptr);
    }

    // And named metadata
    for (auto &NMD : M.named_metadata()) {
        for (unsigned i = 0, e = NMD.getNumOperands(); i != e; ++i)
            NMD.setOperand(i, MapMetadata(NMD.getOperand(i), VMap));
    }

    // Now that we've duplicated everything, remove the old references
    for (GlobalVariable *GV : Globals)
        GV->eraseFromParent();
    for (GlobalAlias *GA : Aliases)
        GA->eraseFromParent();
    for (Function *F : Functions)
        F->eraseFromParent();

    // Finally, remangle calls to intrinsic
    for (Module::iterator FI = M.begin(), FE = M.end(); FI != FE;) {
        Function *F = &*FI++;
        if (auto Remangled = Intrinsic::remangleIntrinsicFunction(F)) {
            F->replaceAllUsesWith(*Remangled);
            F->eraseFromParent();
        }
    }

    return true;
}


RemoveAddrspacesPass::RemoveAddrspacesPass() : RemoveAddrspacesPass(removeAllAddrspaces) {}

PreservedAnalyses RemoveAddrspacesPass::run(Module &M, ModuleAnalysisManager &AM) {
    bool modified = removeAddrspaces(M, ASRemapper);
#ifdef JL_VERIFY_PASSES
    assert(!verifyLLVMIR(M));
#endif
    if (modified) {
        return PreservedAnalyses::allInSet<CFGAnalyses>();
    } else {
        return PreservedAnalyses::all();
    }
}


//
// Julia-specific pass
//

unsigned removeJuliaAddrspaces(unsigned AS)
{
    if (AddressSpace::FirstSpecial <= AS && AS <= AddressSpace::LastSpecial)
        return AddressSpace::Generic;
    else
        return AS;
}


PreservedAnalyses RemoveJuliaAddrspacesPass::run(Module &M, ModuleAnalysisManager &AM) {
    return RemoveAddrspacesPass(removeJuliaAddrspaces).run(M, AM);
}
