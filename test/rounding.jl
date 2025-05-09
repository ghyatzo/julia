# This file is a part of Julia. License is MIT: https://julialang.org/license

# Small sanity tests to ensure changing the rounding of float functions work
using Base.MathConstants

using Test

@testset "Float64 checks" begin
    # a + b returns a number exactly between prevfloat(1.) and 1., so its
    # final result depends strongly on the utilized rounding direction.
    a = prevfloat(0.5)
    b = 0.5
    c = 0x1p-54
    d = prevfloat(1.)

    @testset "Default rounding direction, RoundNearest" begin
        @test a + b === 1.
        @test - a - b === -1.
        @test a - b === -c
        @test b - a === c
    end
end

@testset "Float32 checks" begin
    a32 = prevfloat(0.5f0)
    b32 = 0.5f0
    c32 = (1.f0 - prevfloat(1.f0))/2
    d32 = prevfloat(1.0f0)

    @testset "Default rounding direction, RoundNearest" begin
        @test a32 + b32 === 1.0f0
        @test - a32 - b32 === -1.0f0
        @test a32 - b32 === -c32
        @test b32 - a32 === c32
    end
end

@testset "convert with rounding" begin
    for v = [sqrt(2),-1/3,nextfloat(1.0),prevfloat(1.0),nextfloat(-1.0),
             prevfloat(-1.0),nextfloat(0.0),prevfloat(0.0)]

        pn = Float32(v,RoundNearest)
        @test pn == convert(Float32,v)

        pz = Float32(v,RoundToZero)
        @test abs(pz) <= abs(v) < nextfloat(abs(pz))
        @test signbit(pz) == signbit(v)

        pd = Float32(v,RoundDown)
        @test pd <= v < nextfloat(pd)

        pu = Float32(v,RoundUp)
        @test prevfloat(pu) < v <= pu

        @test pn == pd || pn == pu
        @test v > 0 ? pz == pd : pz == pu
        @test pu - pd == eps(pz)
    end

    for T in [Float16,Float32,Float64]
        for v in [sqrt(big(2.0)),-big(1.0)/big(3.0),nextfloat(big(1.0)),
                  prevfloat(big(1.0)),nextfloat(big(0.0)),prevfloat(big(0.0)),
                  pi,ℯ,eulergamma,catalan,golden,
                  typemax(Int64),typemax(UInt64),typemax(Int128),typemax(UInt128),0xa2f30f6001bb2ec6]
            pn = T(v,RoundNearest)
            @test pn == convert(T,BigFloat(v))
            pz = T(v,RoundToZero)
            @test pz == setrounding(()->convert(T,BigFloat(v)), BigFloat, RoundToZero)
            pd = T(v,RoundDown)
            @test pd == setrounding(()->convert(T,BigFloat(v)), BigFloat, RoundDown)
            pu = T(v,RoundUp)
            @test pu == setrounding(()->convert(T,BigFloat(v)), BigFloat, RoundUp)

            @test pn == pd || pn == pu
            @test v > 0 ? pz == pd : pz == pu
            @test isinf(pu) || pu - pd == eps(pz)
        end
    end
end
@testset "fenv" begin
    @test Base.Rounding.from_fenv(Base.Rounding.to_fenv(RoundNearest)) == RoundNearest
    @test Base.Rounding.from_fenv(Base.Rounding.to_fenv(RoundToZero)) == RoundToZero
    @test Base.Rounding.from_fenv(Base.Rounding.to_fenv(RoundUp)) == RoundUp
    @test Base.Rounding.from_fenv(Base.Rounding.to_fenv(RoundDown)) == RoundDown
    @test_throws ArgumentError Base.Rounding.from_fenv(-99)
end

@testset "round error throwing" begin
    badness = 1//0
    @test_throws DivideError round(Int64,badness,RoundNearestTiesAway)
    @test_throws DivideError round(Int64,badness,RoundNearestTiesUp)
end

@testset "rounding properties" for Tf in [Float16,Float32,Float64]
    # these should hold for all u, but we just test the smallest and largest
    # of each binade

    for i in exponent(floatmin(Tf)):exponent(floatmax(Tf))
        for u in [ldexp(Tf(1.0), i), -ldexp(Tf(1.0), i),
                  ldexp(prevfloat(Tf(2.0)), i), -ldexp(prevfloat(Tf(2.0)), i)]

            r = round(u, RoundNearest)
            if isfinite(u)
                @test isfinite(r)
                @test isinteger(r)
                @test abs(r-u) < 0.5 || abs(r-u) == 0.5 && isinteger(r/2)
                @test signbit(u) == signbit(r)
            else
                @test u === r
            end

            r = round(u, RoundNearestTiesAway)
            if isfinite(u)
                @test isfinite(r)
                @test isinteger(r)
                @test abs(r-u) < 0.5 || (r-u) == copysign(0.5,u)
                @test signbit(u) == signbit(r)
            else
                @test u === r
            end

            r = round(u, RoundNearestTiesUp)
            if isfinite(u)
                @test isfinite(r)
                @test isinteger(r)
                @test -0.5 < r-u <= 0.5
                @test signbit(u) == signbit(r)
            else
                @test u === r
            end

            r = round(u, RoundFromZero)
            if isfinite(u)
                @test isfinite(r)
                @test isinteger(r)
                @test signbit(u) ? (r == floor(u)) : (r == ceil(u))
                @test signbit(u) == signbit(r)
            else
                @test u === r
            end
        end
    end
end

@testset "rounding difficult values" begin
    for x = Int64(2)^53-10:Int64(2)^53+10
        y = Float64(x)
        i = trunc(Int64,y)
        @test Int64(trunc(y)) == i
        @test Int64(round(y)) == i
        @test Int64(floor(y)) == i
        @test Int64(ceil(y))  == i

        @test round(Int64,y)       == i
        @test floor(Int64,y)       == i
        @test ceil(Int64,y)        == i
    end

    for x = 2^24-10:2^24+10
        y = Float32(x)
        i = trunc(Int,y)
        @test Int(trunc(y)) == i
        @test Int(round(y)) == i
        @test Int(floor(y)) == i
        @test Int(ceil(y))  == i
        @test round(Int,y)     == i
        @test floor(Int,y)     == i
        @test ceil(Int,y)      == i
    end

    # rounding vectors
    let ≈(x,y) = x==y && typeof(x)==typeof(y)
        for t in [Float32,Float64]
            # try different vector lengths
            for n in [0,3,255,256]
                r = (1:n) .- div(n,2)
                y = t[x/4 for x in r]
                @test trunc.(y) ≈ t[div(i,4) for i in r]
                @test floor.(y) ≈ t[i>>2 for i in r]
                @test ceil.(y)  ≈ t[(i+3)>>2 for i in r]
                @test round.(y) ≈ t[(i+1+isodd(i>>2))>>2 for i in r]
                @test broadcast(x -> round(x, RoundNearestTiesAway), y) ≈ t[(i+1+(i>=0))>>2 for i in r]
                @test broadcast(x -> round(x, RoundNearestTiesUp), y) ≈ t[(i+2)>>2 for i in r]
                @test broadcast(x -> round(x, RoundFromZero), y) ≈ t[(i+3*(i>=0))>>2 for i in r]
            end
        end
    end

    @test_throws InexactError round(Int,Inf)
    @test_throws InexactError round(Int,NaN)
    @test round(Int,2.5) == 2
    @test round(Int,1.5) == 2
    @test round(Int,-2.5) == -2
    @test round(Int,-1.5) == -2
    @test round(Int,2.5,RoundNearestTiesAway) == 3
    @test round(Int,1.5,RoundNearestTiesAway) == 2
    @test round(Int,2.5,RoundNearestTiesUp) == 3
    @test round(Int,1.5,RoundNearestTiesUp) == 2
    @test round(Int,-2.5,RoundNearestTiesAway) == -3
    @test round(Int,-1.5,RoundNearestTiesAway) == -2
    @test round(Int,-2.5,RoundNearestTiesUp) == -2
    @test round(Int,-1.5,RoundNearestTiesUp) == -1
    @test round(Int,-1.9) == -2
    @test round(Int,nextfloat(1.0),RoundFromZero) == 2
    @test round(Int,-nextfloat(1.0),RoundFromZero) == -2
    @test round(Int,prevfloat(1.0),RoundFromZero) == 1
    @test round(Int,-prevfloat(1.0),RoundFromZero) == -1
    @test_throws InexactError round(Int64, 9.223372036854776e18)
    @test       round(Int64, 9.223372036854775e18) == 9223372036854774784
    @test_throws InexactError round(Int64, -9.223372036854778e18)
    @test       round(Int64, -9.223372036854776e18) == typemin(Int64)
    @test_throws InexactError round(UInt64, 1.8446744073709552e19)
    @test       round(UInt64, 1.844674407370955e19) == 0xfffffffffffff800
    @test_throws InexactError round(Int32, 2.1474836f9)
    @test       round(Int32, 2.1474835f9) == 2147483520
    @test_throws InexactError round(Int32, -2.147484f9)
    @test       round(Int32, -2.1474836f9) == typemin(Int32)
    @test_throws InexactError round(UInt32, 4.2949673f9)
    @test       round(UInt32, 4.294967f9) == 0xffffff00


    for Ti in [Int,UInt]
        for Tf in [Float16,Float32,Float64]

            @test round(Ti,Tf(-0.0)) == 0
            @test round(Ti,Tf(-0.0),RoundNearestTiesAway) == 0
            @test round(Ti,Tf(-0.0),RoundNearestTiesUp) == 0

            @test round(Ti, Tf(0.5)) == 0
            @test round(Ti, Tf(0.5), RoundNearestTiesAway) == 1
            @test round(Ti, Tf(0.5), RoundNearestTiesUp) == 1

            @test round(Ti, prevfloat(Tf(0.5))) == 0
            @test round(Ti, prevfloat(Tf(0.5)), RoundNearestTiesAway) == 0
            @test round(Ti, prevfloat(Tf(0.5)), RoundNearestTiesUp) == 0

            @test round(Ti, nextfloat(Tf(0.5))) == 1
            @test round(Ti, nextfloat(Tf(0.5)), RoundNearestTiesAway) == 1
            @test round(Ti, nextfloat(Tf(0.5)), RoundNearestTiesUp) == 1

            @test round(Ti, Tf(-0.5)) == 0
            @test round(Ti, Tf(-0.5), RoundNearestTiesUp) == 0

            @test round(Ti, nextfloat(Tf(-0.5))) == 0
            @test round(Ti, nextfloat(Tf(-0.5)), RoundNearestTiesAway) == 0
            @test round(Ti, nextfloat(Tf(-0.5)), RoundNearestTiesUp) == 0

            if Ti <: Signed
                @test round(Ti, Tf(-0.5), RoundNearestTiesAway) == -1
                @test round(Ti, prevfloat(Tf(-0.5))) == -1
                @test round(Ti, prevfloat(Tf(-0.5)), RoundNearestTiesAway) == -1
                @test round(Ti, prevfloat(Tf(-0.5)), RoundNearestTiesUp) == -1
            else
                @test_throws InexactError round(Ti, Tf(-0.5), RoundNearestTiesAway)
                @test_throws InexactError round(Ti, prevfloat(Tf(-0.5)))
                @test_throws InexactError round(Ti, prevfloat(Tf(-0.5)), RoundNearestTiesAway)
                @test_throws InexactError round(Ti, prevfloat(Tf(-0.5)), RoundNearestTiesUp)
            end
        end
    end

    # numbers that can't be rounded by trunc(x+0.5)
    @test round(Int64, 2.0^52 + 1) == 4503599627370497
    @test round(Int32, 2.0f0^23 + 1) == 8388609
end

# custom rounding and significant-digit ops
@testset "rounding to digits relative to the decimal point" begin
    @test round(pi) ≈ 3.
    @test round(pi, base=10) ≈ 3.
    @test round(pi, digits=0) ≈ 3.
    @test round(pi, digits=1) ≈ 3.1
    @test round(pi, digits=3, base=2) ≈ 3.125
    @test round(pi, sigdigits=1) ≈ 3.
    @test round(pi, sigdigits=3) ≈ 3.14
    @test round(pi, sigdigits=4, base=2) ≈ 3.25
    @test round(big(pi)) ≈ big"3."
    @test round(big(pi), digits=0) ≈ big"3."
    @test round(big(pi), digits=1) ≈ big"3.1"
    @test round(big(pi), digits=3, base=2) ≈ big"3.125"
    @test round(big(pi), sigdigits=1) ≈ big"3."
    @test round(big(pi), sigdigits=3) ≈ big"3.14"
    @test round(big(pi), sigdigits=4, base=2) ≈ big"3.25"
    @test round(10*pi, digits=-1) ≈ 30.
    @test round(.1, digits=0) == 0.
    @test round(-.1, digits=0) == -0.
    @test isnan(round(NaN, digits=2))
    @test isinf(round(Inf, digits=2))
    @test isinf(round(-Inf, digits=2))
end
@testset "round vs trunc vs floor vs ceil" begin
    @test round(123.456, digits=1) ≈ 123.5
    @test round(-123.456, digits=1) ≈ -123.5
    @test trunc(123.456, digits=1) ≈ 123.4
    @test trunc(-123.456, digits=1) ≈ -123.4
    @test ceil(123.456, digits=1) ≈ 123.5
    @test ceil(-123.456, digits=1) ≈ -123.4
    @test floor(123.456, digits=1) ≈ 123.4
    @test floor(-123.456, digits=1) ≈ -123.5
end
@testset "rounding with too much (or too few) precision" begin
    for x in (12345.6789, 0, -12345.6789)
        y = float(x)
        @test y == trunc(x, digits=1000)
        @test y == round(x, digits=1000)
        @test y == floor(x, digits=1000)
        @test y == ceil(x, digits=1000)
    end
    let x = 12345.6789
        @test 0.0 == trunc(x, digits=-1000)
        @test 0.0 == round(x, digits=-1000)
        @test 0.0 == floor(x, digits=-1000)
        @test Inf == ceil(x, digits=-1000)
    end
    let x = -12345.6789
        @test -0.0 == trunc(x, digits=-1000)
        @test -0.0 == round(x, digits=-1000)
        @test -Inf == floor(x, digits=-1000)
        @test -0.0 == ceil(x, digits=-1000)
    end
    let x = 0.0
        @test 0.0 == trunc(x, digits=-1000)
        @test 0.0 == round(x, digits=-1000)
        @test 0.0 == floor(x, digits=-1000)
        @test 0.0 == ceil(x, digits=-1000)
    end
end
@testset "rounding in other bases" begin
    @test round(pi, digits = 2, base = 2) ≈ 3.25
    @test round(pi, digits = 3, base = 2) ≈ 3.125
    @test round(pi, digits = 3, base = 5) ≈ 3.144
end
@testset "vectorized trunc/round/floor/ceil with digits/base argument" begin
    a = rand(2, 2, 2)
    for f in (round, trunc, floor, ceil)
        @test f.(a[:, 1, 1],  digits=2) == map(x->f(x, digits=2), a[:, 1, 1])
        @test f.(a[:, :, 1],  digits=2) == map(x->f(x, digits=2), a[:, :, 1])
        @test f.(a,  digits=9, base = 2) == map(x->f(x, digits=9, base = 2), a)
        @test f.(a[:, 1, 1], digits=9, base = 2) == map(x->f(x, digits=9, base = 2), a[:, 1, 1])
        @test f.(a[:, :, 1], digits=9, base = 2) == map(x->f(x, digits=9, base = 2), a[:, :, 1])
        @test f.(a, digits=9, base = 2) == map(x->f(x, digits=9, base = 2), a)
    end
end

@testset "rounding for F32/F64" begin
    for T in [Float32, Float64]
        old = rounding(T)
        Base.Rounding.setrounding_raw(T, Base.Rounding.JL_FE_TOWARDZERO)
        @test rounding(T) == RoundToZero
        @test round(T(2.7)) == T(2.0)
        Base.Rounding.setrounding_raw(T, Base.Rounding.to_fenv(old))
    end
end

@testset "rounding floats with specified return type #50778" begin
    @test round(Float64, 1.2) === 1.0
    @test round(Float32, 1e60) === Inf32
    x = floatmax(Float32)-1.0
    @test round(Float32, x) == x
end

@testset "rounding complex numbers (#42060, #47128)" begin
    # 42060
    @test ceil(Complex(4.6, 2.2)) === Complex(5.0, 3.0)
    @test floor(Complex(4.6, 2.2)) === Complex(4.0, 2.0)
    @test trunc(Complex(4.6, 2.2)) === Complex(4.0, 2.0)
    @test round(Complex(4.6, 2.2)) === Complex(5.0, 2.0)
    @test ceil(Complex(-4.6, -2.2)) === Complex(-4.0, -2.0)
    @test floor(Complex(-4.6, -2.2)) === Complex(-5.0, -3.0)
    @test trunc(Complex(-4.6, -2.2)) === Complex(-4.0, -2.0)
    @test round(Complex(-4.6, -2.2)) === Complex(-5.0, -2.0)

    # 47128
    @test round(Complex{Int}, Complex(4.6, 2.2)) === Complex(5, 2)
    @test ceil(Complex{Int}, Complex(4.6, 2.2)) === Complex(5, 3)
end

@testset "rounding to custom integers" begin
    struct Int50812 <: Integer
        x::Int
    end
    @test round(Int50812, 1.2) === Int50812(1)
    @test round(Int50812, π) === Int50812(3)
    @test ceil(Int50812, π) === Int50812(4)
end

const MPFRRM = Base.MPFR.MPFRRoundingMode

function mpfr_to_ieee(::Type{Float32}, x::BigFloat, r::MPFRRM)
    ccall((:mpfr_get_flt, Base.MPFR.libmpfr), Float32, (Ref{BigFloat}, MPFRRM), x, r)
end
function mpfr_to_ieee(::Type{Float64}, x::BigFloat, r::MPFRRM)
    ccall((:mpfr_get_d, Base.MPFR.libmpfr), Float64, (Ref{BigFloat}, MPFRRM), x, r)
end

function mpfr_to_ieee(::Type{G}, x::BigFloat, r::RoundingMode) where {G}
    mpfr_to_ieee(G, x, convert(MPFRRM, r))
end

const mpfr_rounding_modes = map(
    Base.Fix1(convert, MPFRRM),
    (RoundNearest, RoundToZero, RoundFromZero, RoundDown, RoundUp)
)

sample_float(::Type{T}, e::Integer) where {T<:AbstractFloat} = ldexp(rand(T) + true, e)::T

function float_samples(::Type{T}, exponents, n::Int) where {T<:AbstractFloat}
    ret = T[]
    for e ∈ exponents, i ∈ 1:n
        push!(ret, sample_float(T, e), -sample_float(T, e))
    end
    ret
end

# a reasonable range of values for testing behavior between 1:200
const fib200 = [1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 200]

@testset "IEEEFloat(::BigFloat) against MPFR" begin
    for pr ∈ fib200
        setprecision(BigFloat, pr) do
            exp = exponent(floatmax(Float64)) + 10
            bf_samples = float_samples(BigFloat, (-exp):exp, 20) # about 82680 random values
            for mpfr_rm ∈ mpfr_rounding_modes, bf ∈ bf_samples, F ∈ (Float32, Float64)
                @test (
                    mpfr_to_ieee(F, bf, mpfr_rm) ===
                    F(bf, mpfr_rm) === F(bf, convert(RoundingMode, mpfr_rm))
                )
            end
        end
    end
end

const native_rounding_modes = (
    RoundNearest, RoundNearestTiesAway, RoundNearestTiesUp,
    RoundToZero, RoundFromZero, RoundUp, RoundDown
)

# Checks that each rounding mode is faithful.
@testset "IEEEFloat(::BigFloat) faithful rounding" begin
    for pr ∈ fib200
        setprecision(BigFloat, pr) do
            exp = 500
            bf_samples = float_samples(BigFloat, (-exp):exp, 20) # about 40040 random values
            for rm ∈ (mpfr_rounding_modes..., Base.MPFR.MPFRRoundFaithful,
                      native_rounding_modes...),
                bf ∈ bf_samples,
                F ∈ (Float16, Float32, Float64)
                f = F(bf, rm)
                @test (f === F(bf, RoundDown)) | (f === F(bf, RoundUp))
            end
        end
    end
end

@testset "round(Int, -Inf16) should throw (#51113)" begin
    @test_throws InexactError round(Int32, -Inf16)
    @test_throws InexactError round(Int64, -Inf16)
    @test_throws InexactError round(Int128, -Inf16)
    # More comprehensive testing is present in test/floatfuncs.jl
end

@testset "floor(<:AbstractFloat, large_number) (#52355)" begin
    @test floor(Float32, 0xffff_ffff) == prevfloat(2f0^32) <= 0xffff_ffff
    @test trunc(Float16, typemax(UInt128)) == floatmax(Float16)
    @test round(Float16, typemax(UInt128)) == Inf16
    for i in [-BigInt(floatmax(Float64)), -BigInt(floatmax(Float64))*100, BigInt(floatmax(Float64)), BigInt(floatmax(Float64))*100]
        f = ceil(Float64, i)
        @test f >= i
        @test isinteger(f) || isinf(f)
        @test prevfloat(f) < i
    end
end

@testset "π to `BigFloat` with `setrounding`" begin
    function irrational_to_big_float(c::AbstractIrrational)
        BigFloat(c)
    end

    function irrational_to_big_float_with_rounding_mode(c::AbstractIrrational, rm::RoundingMode)
        f = () -> irrational_to_big_float(c)
        setrounding(f, BigFloat, rm)
    end

    function irrational_to_big_float_with_rounding_mode_and_precision(c::AbstractIrrational, rm::RoundingMode, prec::Int)
        f = () -> irrational_to_big_float_with_rounding_mode(c, rm)
        setprecision(f, BigFloat, prec)
    end

    for c ∈ (π, MathConstants.γ, MathConstants.catalan)
        for p ∈ 1:40
            @test (
                irrational_to_big_float_with_rounding_mode_and_precision(c, RoundDown, p) < c <
                irrational_to_big_float_with_rounding_mode_and_precision(c, RoundUp, p)
            )
        end
    end
end

@testset "Rounding to floating point types with RoundFromZero #55820" begin
    @testset "Testing float types: $f" for f ∈ (Float16, Float32, Float64, BigFloat)
        @testset "Testing value types: $t" for t ∈ (Bool, Rational{Int8})
            @test iszero(f(zero(t), RoundFromZero))
        end
    end
    @test Float16(100000, RoundToZero) === floatmax(Float16)
    @test Float16(100000, RoundFromZero) === Inf16
    @test Float16(-100000, RoundToZero) === -floatmax(Float16)
    @test Float16(-100000, RoundFromZero) === -Inf16
    @test Float32(nextfloat(0.0), RoundFromZero) === nextfloat(0.0f0)
end
