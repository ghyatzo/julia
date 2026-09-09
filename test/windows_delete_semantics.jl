# Windows deletion semantics tests for the libuv fork.
#
# Run with an existing Julia build (nightly works, no rebuild needed):
#     julia --startup-file=no test/windows_delete_semantics.jl
#
# These tests assert the DESIRED behavior of uv_fs_unlink on Windows:
#   1. POSIX delete semantics: the name disappears from the namespace
#      immediately, even while another handle holds the file open
#      (matching POSIX unlink(2) and DeleteFileW's own docs).
#   2. stat/ispath on a delete-pending name returns false instead of
#      throwing EACCES.
#   3. Rename of an open file (opener shares delete) succeeds —
#      the rename-to-temp fallback relies on this.
#   4. Renaming a delete-pending name reports ENOENT (name is gone),
#      not the misleading EACCES.
#
# Current JuliaLang/libuv (julia-uv2-1.48.0 @ e6b9850) fails 1, 2 and 4.

using Test

@static if !Sys.iswindows()
    println("not windows, nothing to test")
else
    const CREATE_ALWAYS = Cuint(2)
    const GENERIC_WRITE = Cuint(0x40000000)
    const FILE_SHARE_ALL = Cuint(0x7) # READ | WRITE | DELETE
    const FILE_ATTRIBUTE_NORMAL = Cuint(0x80)
    const INVALID_HANDLE_VALUE = reinterpret(Ptr{Cvoid}, -Csize_t(1))

    open_sharing(path) = ccall(:CreateFileW, stdcall, Ptr{Cvoid},
        (Cwstring, Cuint, Cuint, Ptr{Cvoid}, Cuint, Cuint, Ptr{Cvoid}),
        path, GENERIC_WRITE, FILE_SHARE_ALL, C_NULL, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, C_NULL)
    closehandle(h) = ccall(:CloseHandle, stdcall, Int32, (Ptr{Cvoid},), h) == 0 &&
        error("CloseHandle failed")

    @testset "windows delete semantics" begin
        d = mktempdir(; cleanup=true)
        p = joinpath(d, "t.txt")

        # open a handle that shares delete, keep it open across the unlink
        h = open_sharing(p)
        @test h != C_NULL
        try
            Base.Filesystem.unlink(p)

            # 1. POSIX semantics: name must be gone immediately
            @test readdir(d) == String[]

            # 2. stat on the (formerly) delete-pending name must not throw
            @test !ispath(p)
        finally
            closehandle(h)
        end
        @test readdir(d) == String[] # fully gone after the handle closed

        # 3. regression guard: rename works while the opener shares delete
        p2 = joinpath(d, "rename_me.txt")
        h2 = open_sharing(p2)
        @test h2 != C_NULL
        @test (Base.rename(p2, joinpath(d, "renamed.txt")); true)
        closehandle(h2)

        # 4. unlink, then rename the now-gone name: ENOENT, not EACCES
        p3 = joinpath(d, "delete_pending.txt")
        h3 = open_sharing(p3)
        Base.Filesystem.unlink(p3)
        err = try
            Base.rename(p3, joinpath(d, "x.txt")); nothing
        catch e
            e
        end
        @test err isa Base.IOError
        @test err.code == Base.UV_ENOENT
        closehandle(h3)
    end
end
