# Behavioral probe for the proposed uv_fs_unlink fallback on Windows.
#
# Replicates, via direct Win32 ccalls, the call sequence a libuv patch would
# perform (unlink -> GetVolumePathNameW -> same-volume temp dir -> MoveFileExW
# -> deferred delete), and records what happens for each holder class:
#   S1 baseline file (no holder)
#   S2 holder with FILE_SHARE_DELETE (same process)
#   S3 loaded DLL (dlopen)          -> the rename-to-temp target case
#   S4 mmap'd file                  -> the mapped-view case
#   S5 cross-volume rename          -> ERROR_NOT_SAME_DEVICE expected
#   S6 foreign process holding without FILE_SHARE_DELETE -> retry case
#
# Run: julia --startup-file=no test/win_delete_fallback_probe.jl

using Libdl, Mmap

function win32_result(ok::Bool, what::String)
    if ok
        println("   ", what, ": OK")
    else
        e = ccall(:GetLastError, stdcall, Cuint, ())
        println("   ", what, ": FAIL (Win32 error $e)")
    end
    return ok
end

volume_path(p) = begin
    buf = Vector{UInt16}(undef, 32768)
    ok = ccall(:GetVolumePathNameW, stdcall, Int32, (Cwstring, Ptr{UInt16}, Cuint), p, buf, length(buf))
    ok == 0 && error("GetVolumePathNameW failed for $p")
    n = something(findfirst(iszero, buf))
    transcode(String, view(buf, 1:n-1))
end

hidden_dir(p) = begin
    mkpath(p)
    ccall(:SetFileAttributesW, stdcall, Int32, (Cwstring, Cuint), p, 0x2) # FILE_ATTRIBUTE_HIDDEN
    p
end

rename_win(src, dst) = ccall(:MoveFileExW, stdcall, Int32, (Cwstring, Cwstring, Cuint), src, dst, 0) != 0

function report(f, name::String)
    println("=== $name ===")
    try
        f()
    catch e
        println("   EXCEPTION: ", sprint(showerror, e))
    end
end

Sys.iswindows() || error("windows only")
println("libuv: ", unsafe_string(ccall(:uv_version_string, Cstring, ())), "\n")

mktempdir() do root
    # ---------- S1: baseline, no holder ----------
    report("S1 baseline file, no holder") do
        p = joinpath(root, "s1.txt"); write(p, "x")
        try
            Base.Filesystem.unlink(p); println("   direct unlink: OK")
        catch e; println("   direct unlink: FAIL $e") end
    end

    # ---------- S2: holder with FILE_SHARE_DELETE ----------
    report("S2 holder with FILE_SHARE_DELETE") do
        p = joinpath(root, "s2.txt"); write(p, "x")
        h = ccall(:CreateFileW, stdcall, Ptr{Cvoid},
            (Cwstring, Cuint, Cuint, Ptr{Cvoid}, Cuint, Cuint, Ptr{Cvoid}),
            p, 0x40000000, 0x7, C_NULL, 2, 0x80, C_NULL) # share all
        try
            Base.Filesystem.unlink(p)
            println("   unlink while open: OK (marked for delete)")
            println("   name lingers while open: ", any(==("s2.txt"), readdir(root)))
        finally
            ccall(:CloseHandle, stdcall, Int32, (Ptr{Cvoid},), h)
        end
        println("   name after close: ", any(==("s2.txt"), readdir(root)))
    end

    # ---------- S3: loaded DLL ----------
    report("S3 loaded DLL (dlopen)") do
        workdir = joinpath(root, "s3"); mkpath(workdir)
        src = joinpath(Sys.BINDIR, "libjulia-internal.dll")
        src = isfile(src) ? src : filter(endswith(".dll"), readdir(Sys.BINDIR, join=true))[1]
        dll = joinpath(workdir, "probe_copy.dll")
        cp(src, dll; force=true)
        h = Libdl.dlopen(dll)                       # load the copy
        try
            try
                Base.Filesystem.unlink(dll); println("   unlink loaded dll: OK ?!")
            catch e; println("   unlink loaded dll: FAIL (", typeof(e).name.name, ")") end

            win32_result(rename_win(dll, joinpath(workdir, "probe_moved.dll")), "rename while loaded, same dir")
            println("   dlsym after rename: ", !isnothing(Libdl.dlsym_e(h, :uv_version_string)))

            # rename out of the dir being deleted, into a same-volume hidden temp dir
            tgt = joinpath(hidden_dir(joinpath(root, "s3_junk")), "probe_moved.dll")
            win32_result(rename_win(joinpath(workdir, "probe_moved.dll"), tgt), "rename to other dir, same volume")
            println("   workdir now: ", readdir(workdir), " -> rmdir: ")
            try rm(workdir, recursive=true); println("      OK") catch e; println("      FAIL $e") end

            Libdl.dlclose(h); h = C_NULL
            try
                Base.Filesystem.unlink(tgt); println("   delete after dlclose: OK")
            catch e; println("   delete after dlclose: FAIL $e") end
        finally
            h != C_NULL && Libdl.dlclose(h)
        end
    end

    # ---------- S4: mmap'd file ----------
    report("S4 mmap'd file (mapped view)") do
        workdir = joinpath(root, "s4"); mkpath(workdir)
        p = joinpath(workdir, "m.txt"); write(p, repeat("y", 8192))
        io = open(p, "r+")
        m = Mmap.mmap(io; grow=false)
        mapped_ok = false
        try
            try
                Base.Filesystem.unlink(p); println("   unlink while mapped: OK ?!")
            catch e; println("   unlink while mapped: FAIL (", typeof(e).name.name, ")") end
            win32_result(rename_win(p, joinpath(workdir, "m_moved.txt")), "rename while mapped")
            println("   mapped data intact after rename: ", m[1] == UInt8('y'))
            println("   workdir now: ", readdir(workdir))
        finally
            finalize(m) # unmap deterministically before close
            close(io)
        end
        try
            Base.Filesystem.unlink(joinpath(workdir, "m_moved.txt")); println("   delete after close: OK")
        catch e; println("   delete after unmap: FAIL $e") end
    end

    # ---------- S4b: mapped view with share-delete handles ----------
    # Disambiguates S4: does a mapped view block rename when every handle
    # shares delete? (This is the case a posix-delete uv patch would hit.)
    report("S4b mapped view, all handles share delete") do
        workdir = joinpath(root, "s4b"); mkpath(workdir)
        p = joinpath(workdir, "m2.txt"); write(p, repeat("z", 8192))
        h = ccall(:CreateFileW, stdcall, Ptr{Cvoid},
            (Cwstring, Cuint, Cuint, Ptr{Cvoid}, Cuint, Cuint, Ptr{Cvoid}),
            p, 0x80000000|0x40000000, 0x7, C_NULL, 3, 0x80, C_NULL) # RDWR|share all|OPEN_EXISTING
        @assert h != reinterpret(Ptr{Cvoid}, -Csize_t(1)) "CreateFileW failed"
        map_ = ccall(:CreateFileMappingW, stdcall, Ptr{Cvoid},
            (Ptr{Cvoid}, Ptr{Cvoid}, Cuint, Cuint, Cuint, Cwstring),
            h, C_NULL, 0x4, 0, 0, "") # PAGE_READWRITE
        view_ = ccall(:MapViewOfFile, stdcall, Ptr{Cvoid},
            (Ptr{Cvoid}, Cuint, Cuint, Cuint, Csize_t), map_, 0x4, 0, 0, 0)
        try
            try
                Base.Filesystem.unlink(p); println("   unlink while mapped (share-delete): OK ?!")
            catch e; println("   unlink while mapped (share-delete): FAIL (", typeof(e).name.name, ")") end
            win32_result(rename_win(p, joinpath(workdir, "m_moved.txt")), "rename while mapped (share-delete)")
            println("   workdir now: ", readdir(workdir))
            println("   view readable: ", unsafe_load(convert(Ptr{UInt8}, view_)) == UInt8('z'))
        finally
            ccall(:UnmapViewOfFile, stdcall, Int32, (Ptr{Cvoid},), view_)
            ccall(:CloseHandle, stdcall, Int32, (Ptr{Cvoid},), map_)
            ccall(:CloseHandle, stdcall, Int32, (Ptr{Cvoid},), h)
        end
        try
            Base.Filesystem.unlink(joinpath(workdir, "m_moved.txt")); println("   delete after unmap: OK")
        catch e; println("   delete after unmap: FAIL $e") end
    end

    # ---------- S5: cross-volume rename ----------
    report("S5 cross-volume rename") do
        drives = collect('A':'Z')
        drives = filter(d -> isdir("$(d):\\"), drives)
        println("   volumes present: ", drives)
        if length(drives) < 2
            println("   SKIPPED: need a second volume to test ERROR_NOT_SAME_DEVICE")
        else
            p = joinpath(root, "s5.txt"); write(p, "x")
            win32_result(rename_win(p, "$(drives[end]):\\jl_probe_s5.txt"), "cross-volume MoveFileExW")
            rm("$(drives[end]):\\jl_probe_s5.txt"; force=true)
        end
    end

    # ---------- S6: foreign process, no FILE_SHARE_DELETE ----------
    report("S6 foreign process holder, no FILE_SHARE_DELETE") do
        p = joinpath(root, "s6.txt"); write(p, "x")
        marker = joinpath(root, "s6_ready"); rm(marker; force=true)
        holder_cmd = "Start-Sleep -Milliseconds 300; \$fs=[System.IO.File]::Open('$p','Open','Read','Read'); Set-Content -Path '$marker' -Value held; Start-Sleep -Seconds 4; \$fs.Close()"
        proc = run(`powershell -NoProfile -Command $holder_cmd`; wait=false)
        for _ in 1:60; isfile(marker) && break; sleep(0.2); end # wait until holder really has the file
        println("   holder ready: ", isfile(marker))
        try
            Base.Filesystem.unlink(p); println("   unlink while foreign-held: OK ?!")
        catch e; println("   unlink while foreign-held: FAIL (", typeof(e).name.name, ")") end
        win32_result(rename_win(p, joinpath(root, "s6_moved.txt")), "rename while foreign-held")
        wait(proc)  # holder releases
        try
            Base.Filesystem.unlink(p); println("   unlink after holder released: OK")
        catch e; println("   unlink after holder released: FAIL $e") end
    end
end
