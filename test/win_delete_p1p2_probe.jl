# Prototypes for the two Julia-side delete patches.
#
# P1: replace ios.c's Windows `_wopen` (no FILE_SHARE_DELETE) with
#     CreateFileW(share=READ|WRITE|DELETE) + _open_osfhandle.
# P2: bounded retry with backoff+jitter, for UV_EBUSY only.
#
# Run: julia --startup-file=no test/win_delete_p1p2_probe.jl

using Libdl

const INVALID_HANDLE_VALUE = reinterpret(Ptr{Cvoid}, -Csize_t(1))
const GENERIC_READ  = Cuint(0x80000000)
const GENERIC_WRITE = Cuint(0x40000000)
const FILE_APPEND_DATA = Cuint(0x0004)
const SHARE_ALL = Cuint(0x1 | 0x2 | 0x4)      # READ | WRITE | DELETE
const SHARE_RW  = Cuint(0x1 | 0x2)            # READ | WRITE  (CRT-like, no DELETE)
const OPEN_EXISTING = Cuint(3)
const OPEN_ALWAYS   = Cuint(4)
const CREATE_ALWAYS = Cuint(2)
const FILE_ATTRIBUTE_NORMAL = Cuint(0x80)
const O_BINARY = Int32(0x8000)
const O_APPEND = Int32(0x0008)

"CreateFileW with an explicit share mode. Returns the HANDLE."
function create_file(path, access, share, disposition)
    h = ccall(:CreateFileW, stdcall, Ptr{Cvoid},
        (Cwstring, Cuint, Cuint, Ptr{Cvoid}, Cuint, Cuint, Ptr{Cvoid}),
        path, access, share, C_NULL, disposition, FILE_ATTRIBUTE_NORMAL, C_NULL)
    h == INVALID_HANDLE_VALUE && error("CreateFileW($path) failed: Win32 error $(ccall(:GetLastError, stdcall, Cuint, ()))")
    return h
end

"P1 mechanism: hand the HANDLE to the CRT as an fd, then wrap it as an IOStream."
function open_share_delete(path; read::Bool=true, write::Bool=true, creat::Bool=false)
    access = (read ? GENERIC_READ : Cuint(0)) | (write ? GENERIC_WRITE : Cuint(0))
    fd = ccall(:_open_osfhandle, cdecl, Int32, (Ptr{Cvoid}, Int32),
               create_file(path, access, SHARE_ALL,
                           creat ? OPEN_ALWAYS : OPEN_EXISTING),
               O_BINARY)
    fd == -1 && error("_open_osfhandle failed")
    return Base.fdio(fd, true)
end

"P2 policy: retry UV_EBUSY only, with exponential backoff and jitter."
function retry_ebusy(f; max_attempts::Int=8, base_ms::Int=10, max_ms::Int=640, trace=false)
    delay = base_ms
    for attempt in 1:max_attempts
        try
            return f()
        catch e
            transient = e isa Base.IOError && e.code == Base.UV_EBUSY
            if !transient || attempt == max_attempts
                rethrow()
            end
            jitter = Int(Libc.rand() % max(1, delay ÷ 2))
            trace && println("      attempt $attempt: EBUSY, waiting $(delay + jitter) ms")
            sleep((delay + jitter) / 1000)
            delay = min(delay * 2, max_ms)
        end
    end
end

unlink_code(f) = try (f(); "ok") catch e; e isa Base.IOError ? "code $(e.code)" : "error" end

root = mktempdir()
println("libuv: ", unsafe_string(ccall(:uv_version_string, Cstring, ())), "\n")

# ---------------------------------------------------------------- P1
println("=== P1: does a share-delete open allow unlink while open? ===")
p = joinpath(root, "p1.txt"); write(p, "hello")

io_crt = open(p, "r+")                       # current Julia path: ios.c _wopen
println("  CRT _wopen, unlink while open:      ", unlink_code(() -> Base.Filesystem.unlink(p)))
close(io_crt)
println("  (CRT handle closed)")

io_sd = open_share_delete(p)
println("  CreateFileW+osfhandle, unlink:      ", unlink_code(() -> Base.Filesystem.unlink(p)))
println("  handle still usable after unlink:   ", (seekstart(io_sd); read(io_sd, String) == "hello"))
close(io_sd)

# P1 append sanity: FILE_APPEND_DATA + O_APPEND must still append
pa = joinpath(root, "p1_append.txt"); write(pa, "AAA")
h = create_file(pa, GENERIC_READ | FILE_APPEND_DATA, SHARE_ALL, OPEN_EXISTING)
fda = ccall(:_open_osfhandle, cdecl, Int32, (Ptr{Cvoid}, Int32), h, O_BINARY | O_APPEND)
io_ap = Base.fdio(fda, true)
write(io_ap, "BBB"); close(io_ap)
println("  append via share-delete handle:     ", read(pa, String) == "AAABBB" ? "AAABBB ok" : "FAILED: $(read(pa, String))")
println("  file still deletable after close:   ", unlink_code(() -> Base.Filesystem.unlink(pa)))

# ---------------------------------------------------------------- P2
println("\n=== P2: retry policy on transient EBUSY (same-process holder, no share-delete) ===")
q = joinpath(root, "p2.txt"); write(q, "x")
h2 = create_file(q, GENERIC_READ, SHARE_RW, OPEN_EXISTING)

println("  no retry:                           ", unlink_code(() -> Base.Filesystem.unlink(q)))

release = @async (sleep(0.4); ccall(:CloseHandle, stdcall, Int32, (Ptr{Cvoid},), h2))
t = @elapsed retry_ebusy(() -> Base.Filesystem.unlink(q); trace=true)
wait(release)
println("  with retry:                         ", ispath(q) ? "STILL PRESENT" : "deleted", ", elapsed $(round(t, digits=2)) s")

print("\n=== P2: permanent EBUSY exhausts the budget (does not hang) ===\n")
r = joinpath(root, "p2_perm.txt"); write(r, "x")
h3 = create_file(r, GENERIC_READ, SHARE_RW, OPEN_EXISTING)
t3 = @elapsed result = unlink_code(() -> retry_ebusy(() -> Base.Filesystem.unlink(r); max_attempts=5, base_ms=10))
println("  result=$result  elapsed=$(round(t3, digits=2)) s  (expected: code -4082, ~0.3 s)")
ccall(:CloseHandle, stdcall, Int32, (Ptr{Cvoid},), h3)

print("\n=== P2: EACCES must NOT be retried (loaded DLL) ===\n")
dll = joinpath(root, "dllcopy.dll")
cp(joinpath(Sys.BINDIR, "libjulia-internal.dll"), dll; force=true)
hdl = Libdl.dlopen(dll)
t4 = @elapsed result4 = unlink_code(() -> retry_ebusy(() -> Base.Filesystem.unlink(dll); trace=true))
println("  result=$result4  elapsed=$(round(t4, digits=4)) s  (expected: code -4092, ~0 s)")
Libdl.dlclose(hdl)

rm(root, recursive=true, force=true)
