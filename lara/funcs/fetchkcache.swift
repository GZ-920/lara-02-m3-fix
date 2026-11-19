//
//  fetchkcache.swift
//  lara
//
//  Created by ruter on 12.05.26.
//

import Foundation

func syskcpath() -> String? {
    guard let hash = getbmhash() else { return nil }
    return "/private/preboot/\(hash)/System/Library/Caches/com.apple.kernelcaches/kernelcache"
}

func larakcpath() -> String? {
    guard let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first else { return nil }
    return docs.appendingPathComponent("kernelcache").path
}

// Every place a running kernelcache can live, including the cryptex layouts
// used by iOS 26 and later.
func kccandidates() -> [String] {
    var paths: [String] = []
    if let p = syskcpath() { paths.append(p) }
    paths.append("/private/preboot/Cryptexes/OS/System/Library/Caches/com.apple.kernelcaches/kernelcache")
    paths.append("/System/Cryptexes/OS/System/Library/Caches/com.apple.kernelcaches/kernelcache")
    paths.append("/System/Library/Caches/com.apple.kernelcaches/kernelcache")
    return paths
}

// Plain file copy into Documents/kernelcache. This needs no kernel structures
// at all - when the sandbox allows the read it is by far the most reliable way
// to obtain a kernelcache that matches the running kernel exactly.
func copykernelcache(_ src: String, _ dst: String) -> Int {
    let s = open(src, O_RDONLY)
    if s < 0 { return -1 }
    defer { close(s) }

    let d = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0o644)
    if d < 0 { return -1 }
    defer { close(d) }

    var buffer = [UInt8](repeating: 0, count: 0x4000)
    var total = 0

    while true {
        let n = buffer.withUnsafeMutableBytes { raw in
            read(s, raw.baseAddress!, 0x4000)
        }
        if n <= 0 { break }

        var written = 0
        while written < n {
            let w = buffer.withUnsafeBytes { raw in
                write(d, raw.baseAddress!.advanced(by: written), n - written)
            }
            if w <= 0 { return -1 }
            written += w
        }
        total += n
    }

    return total
}

func isplausiblekc(_ path: String) -> Bool {
    guard let attrs = try? FileManager.default.attributesOfItem(atPath: path),
          let size = attrs[.size] as? NSNumber,
          size.intValue > 0x400000 else {
        return false
    }

    guard let handle = FileHandle(forReadingAtPath: path) else { return false }
    let head = handle.readData(ofLength: 8)
    handle.closeFile()
    guard head.count == 8 else { return false }

    var header = ""
    for b in head.prefix(4) {
        header += String(format: "%02x", b)
    }
    globallogger.log("(fetchkcache) candidate header: \(header)")

    return head.contains { $0 != 0 }
}

func fetchkcache() -> Bool {
    guard let outpath = larakcpath() else {
        globallogger.log("(fetchkcache) failed to get output path")
        return false
    }

    unlink(outpath)

    // 1. Read the running kernelcache straight off disk.
    for path in kccandidates() {
        if access(path, R_OK) != 0 {
            continue
        }

        globallogger.log("(fetchkcache) reading \(path)")
        let copied = copykernelcache(path, outpath)

        if copied > 0, isplausiblekc(outpath) {
            globallogger.log("(fetchkcache) kernelcache fetch success! (\(copied) bytes)")
            return true
        }

        unlink(outpath)
    }

    globallogger.log("(fetchkcache) direct read unavailable, trying vnode redirect")

    // 2. Legacy vnode redirect. Needs resolved offsets and our own proc, so it
    // only works once the kernel structures are known.
    guard ds_is_ready(),
          ds_get_our_proc() != 0,
          off_proc_p_fd != 0,
          off_filedesc_fd_ofiles != 0,
          off_fileproc_fp_glob != 0,
          off_fileglob_fg_data != 0,
          off_vnode_v_data != 0,
          off_namecache_nc_vp != 0,
          off_namecache_nc_child_tqe_next != 0 else {
        globallogger.log("(fetchkcache) exploit or offsets not ready")
        return false
    }

    guard let kcpath = syskcpath() else {
        globallogger.log("(fetchkcache) failed to get kernelcache path")
        return false
    }

    let fakeread = "/private/preboot/Cryptexes/OS/System/Library/CoreServices/RestoreVersion.plist"

    // Bail out before touching kernel memory when the paths are not accessible
    // (sandboxed context or a layout change in newer iOS). vn_fileredirect
    // would otherwise resolve a bogus vnode and fault inside the kernel.
    if access(kcpath, R_OK) != 0 {
        globallogger.log("(fetchkcache) kernelcache path not readable: \(kcpath)")
        return false
    }
    if access(fakeread, F_OK) != 0 {
        globallogger.log("(fetchkcache) redirect anchor missing: \(fakeread)")
        return false
    }

    var ogvn: UInt64 = 0
    var ogvd: UInt64 = 0

    let redirect = kcpath.withCString { kcCString in
        vn_fileredirect(fakeread, kcCString, &ogvn, &ogvd)
    }
    if !redirect {
        globallogger.log("(fetchkcache) failed to redirect vnode")
        return false
    }

    let src = open(fakeread, O_RDONLY)
    if src < 0 {
        vn_fileunredirect(ogvn, ogvd)
        return false
    }

    let dst = open(outpath, O_WRONLY | O_CREAT | O_TRUNC, 0o644)
    if dst < 0 {
        close(src)
        vn_fileunredirect(ogvn, ogvd)
        return false
    }

    defer {
        close(src)
        close(dst)
        vn_fileunredirect(ogvn, ogvd)
    }

    var buffer = [UInt8](repeating: 0, count: 0x4000)
    let bufferSize = buffer.count
    var totalBytes = 0

    while true {
        let n = buffer.withUnsafeMutableBytes { rawBuffer in
            read(src, rawBuffer.baseAddress!, bufferSize)
        }

        if n < 0 {
            globallogger.log("(fetchkcache) failed to read kernelcache")
            return false
        }

        if n == 0 {
            break
        }

        var written = 0
        while written < n {
            let w = buffer.withUnsafeBytes { rawBuffer in
                write(dst, rawBuffer.baseAddress!.advanced(by: written), n - written)
            }

            if w <= 0 {
                globallogger.log("(fetchkcache) failed to write kernelcache")
                return false
            }

            written += w
        }

        totalBytes += n
    }

    if !FileManager.default.fileExists(atPath: outpath) || totalBytes == 0 {
        globallogger.log("(fetchkcache) kernelcache output missing")
        return false
    }

    globallogger.log("(fetchkcache) kernelcache fetch success! (vnode redirect)")
    return true
}
