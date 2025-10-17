#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# identify_hash.py v6.1-multi
# - Local: hashlib + extras (blake3, pycryptodome) + passlib + optional non-crypto
# - External (--try-external): Try *every* Hashcat mode and *every* John format
#   using your provided files: --valueof known.txt (wordlist), --hashvalue hash.txt (hashes)
#   >>> Now aggregates and reports ALL cracked hashes (not just the first).

import argparse, base64, binascii, hashlib, re, sys, subprocess, tempfile, shutil
from pathlib import Path
from typing import List, Optional, Tuple, Dict

# ===================== Target format helpers =====================

HEX_RE = re.compile(r'^[0-9a-fA-F]+$')
HEX_CLEAN_RE = re.compile(r'[^0-9a-fA-F]')

def clean_hex_fingerprint(s: str) -> str:
    st = s.strip()
    if st.lower().startswith("0x"):
        st = st[2:]
    return HEX_CLEAN_RE.sub("", st)

def clean_target_text(s: str) -> str:
    return "".join(s.split())

def detect_target_format(s: str) -> str:
    st = clean_hex_fingerprint(s)
    return 'hex' if st and len(st) % 2 == 0 and HEX_RE.fullmatch(st) else 'b64'

def normalize_b64(s: str) -> str:
    st = clean_target_text(s)
    return st + ('=' * ((4 - (len(st) % 4)) % 4))

def b64_variants(d: bytes) -> List[str]:
    std = base64.b64encode(d).decode('ascii')
    url = base64.urlsafe_b64encode(d).decode('ascii')
    return list({std, std.rstrip('='), url, url.rstrip('=')})

def hex_variants(d: bytes) -> List[str]:
    hx = binascii.hexlify(d).decode('ascii')
    return [hx, hx.upper()]

def target_bytes_from_hex(s: str) -> Optional[bytes]:
    try:
        return binascii.unhexlify(clean_hex_fingerprint(s))
    except Exception:
        return None

def target_bytes_from_b64(s: str) -> Optional[bytes]:
    try:
        return base64.b64decode(normalize_b64(s), validate=False)
    except Exception:
        return None

def match_digest(digest: bytes, target_str: str, target_kind: str, alg_name: str,
                 variable_len_note: bool = False, source: Optional[str] = None) -> Optional[str]:
    label_src = f" ({source})" if source else ""
    if target_kind == 'hex':
        tgt = clean_hex_fingerprint(target_str).lower()
        for cand in hex_variants(digest):
            if cand.lower() == tgt:
                size_note = f" (digest_size={len(digest)} bytes)" if variable_len_note else ""
                return f"{alg_name}{size_note} [hex]{label_src}"
    else:
        cleaned = clean_target_text(target_str)
        for cand in b64_variants(digest):
            if cand == cleaned:
                size_note = f" (digest_size={len(digest)} bytes)" if variable_len_note else ""
                return f"{alg_name}{size_note} [base64]{label_src}"
    return None

# ===================== hashlib algorithms =====================

def algorithms_order() -> List[str]:
    preferred = [
        "sha1","sha224","sha256","sha384","sha512",
        "sha3_224","sha3_256","sha3_384","sha3_512",
        "shake_128","shake_256",
    ]
    avail = set(hashlib.algorithms_available)
    return [a for a in preferred if a in avail] + sorted(avail - set(preferred))

def try_hashlib_alg(alg: str, data: bytes, target_str: str, target_kind: str,
                    target_len_bytes: Optional[int]) -> Optional[str]:
    try:
        name = alg.lower()
        if name.startswith('shake_'):
            if target_len_bytes is None:
                return None
            h = getattr(hashlib, alg)(); h.update(data)
            digest = h.digest(target_len_bytes)
            return match_digest(digest, target_str, target_kind, alg, variable_len_note=True, source="hashlib")
        elif name.startswith('blake2b'):
            h = hashlib.blake2b(digest_size=target_len_bytes) if (target_len_bytes and 1 <= target_len_bytes <= 64) else hashlib.blake2b()
            h.update(data); digest = h.digest()
            return match_digest(digest, target_str, target_kind, alg, variable_len_note=True, source="hashlib")
        elif name.startswith('blake2s'):
            h = hashlib.blake2s(digest_size=target_len_bytes) if (target_len_bytes and 1 <= target_len_bytes <= 32) else hashlib.blake2s()
            h.update(data); digest = h.digest()
            return match_digest(digest, target_str, target_kind, alg, variable_len_note=True, source="hashlib")
        else:
            h = hashlib.new(alg); h.update(data); digest = h.digest()
            return match_digest(digest, target_str, target_kind, alg, source="hashlib")
    except Exception:
        return None

# ===================== Extra algorithms (BLAKE3, PyCryptodome) =====================

def extra_algorithms():
    extras = []
    try:
        import blake3
        def _blake3(data: bytes, out_len: Optional[int]) -> bytes:
            h = blake3.blake3(data)
            return h.digest(out_len) if out_len else h.digest()
        extras.append(("blake3", _blake3, True, "blake3"))
    except Exception:
        pass
    try:
        from Crypto.Hash import RIPEMD160 as _RIPEMD160
        extras.append(("ripemd160", lambda b, n: _RIPEMD160.new(data=b).digest(), False, "pycryptodome"))
    except Exception:
        pass
    try:
        from Crypto.Hash import MD4 as _MD4
        extras.append(("md4", lambda b, n: _MD4.new(data=b).digest(), False, "pycryptodome"))
    except Exception:
        pass
    try:
        from Crypto.Hash import MD2 as _MD2
        extras.append(("md2", lambda b, n: _MD2.new(data=b).digest(), False, "pycryptodome"))
    except Exception:
        pass
    try:
        from Crypto.Hash import SM3 as _SM3
        extras.append(("sm3", lambda b, n: _SM3.new(data=b).digest(), False, "pycryptodome"))
    except Exception:
        pass
    _Whirlpool = None
    try:
        from Crypto.Hash import Whirlpool as _Whirlpool
    except Exception:
        try:
            from Crypto.Hash import WHIRLPOOL as _Whirlpool
        except Exception:
            _Whirlpool = None
    if _Whirlpool is not None:
        extras.append(("whirlpool", lambda b, n: _Whirlpool.new(data=b).digest(), False, "pycryptodome"))
    _keccak_mod = None
    try:
        from Crypto.Hash import keccak as _keccak_mod
    except Exception:
        try:
            from Crypto.Hash import KECCAK as _keccak_mod
        except Exception:
            _keccak_mod = None
    if _keccak_mod is not None:
        extras += [
            ("keccak_224", lambda b, n, M=_keccak_mod: M.new(data=b, digest_bits=224).digest(), False, "pycryptodome"),
            ("keccak_256", lambda b, n, M=_keccak_mod: M.new(data=b, digest_bits=256).digest(), False, "pycryptodome"),
            ("keccak_384", lambda b, n, M=_keccak_mod: M.new(data=b, digest_bits=384).digest(), False, "pycryptodome"),
            ("keccak_512", lambda b, n, M=_keccak_mod: M.new(data=b, digest_bits=512).digest(), False, "pycryptodome"),
        ]
    return extras

def try_extra_alg(name: str, func, data: bytes, target_str: str, target_kind: str,
                  target_len_bytes: Optional[int], variable_len: bool, source_tag: str) -> Optional[str]:
    try:
        digest = func(data, target_len_bytes)
    except Exception:
        return None
    return match_digest(digest, target_str, target_kind, name, variable_len_note=variable_len, source=source_tag)

# ===================== Passlib (salted/iterated password hashes) =====================

def passlib_schemes():
    schemes = []
    try:
        from passlib.hash import md5_crypt, sha256_crypt, sha512_crypt
        schemes += [("md5_crypt", md5_crypt), ("sha256_crypt", sha256_crypt), ("sha512_crypt", sha512_crypt)]
    except Exception:
        pass
    try:
        from passlib.hash import bcrypt
        schemes.append(("bcrypt", bcrypt))
    except Exception:
        pass
    try:
        from passlib.hash import argon2
        schemes.append(("argon2", argon2))
    except Exception:
        pass
    try:
        from passlib.hash import pbkdf2_sha256, pbkdf2_sha512
        schemes += [("pbkdf2_sha256", pbkdf2_sha256), ("pbkdf2_sha512", pbkdf2_sha512)]
    except Exception:
        pass
    try:
        from passlib.hash import django_pbkdf2_sha256
        schemes.append(("django_pbkdf2_sha256", django_pbkdf2_sha256))
    except Exception:
        pass
    return schemes

def try_passlib(candidate_text: Optional[str], stored: str) -> Optional[str]:
    if candidate_text is None:
        return None
    for name, scheme in passlib_schemes():
        try:
            ident = getattr(scheme, "ident", None)
            if ident:
                if not stored.startswith(ident) and not (name == "bcrypt" and stored.startswith(("$2a$","$2b$","$2y$"))):
                    continue
            if scheme.verify(candidate_text, stored):
                return f"{name} (passlib)"
        except Exception:
            continue
    return None

# ===================== Non-crypto hashes (mmh3, xxhash) =====================

def noncrypto_algorithms():
    misc = []
    try:
        import mmh3
        misc.append(("murmur3_32",  lambda s: mmh3.hash(s, signed=False).to_bytes(4, "big")))
        misc.append(("murmur3_128", lambda s: mmh3.hash128(s, signed=False).to_bytes(16, "big")))
    except Exception:
        pass
    try:
        import xxhash
        misc.append(("xxhash32",  lambda b: xxhash.xxh32(b).digest()))
        misc.append(("xxhash64",  lambda b: xxhash.xxh64(b).digest()))
        try:
            misc.append(("xxhash128", lambda b: xxhash.xxh128(b).digest()))
        except Exception:
            pass
    except Exception:
        pass
    return misc

def try_noncrypto(candidate_bytes: bytes, candidate_text: Optional[str], target_str: str, target_kind: str) -> Optional[str]:
    for name, fn in noncrypto_algorithms():
        try:
            if name.startswith("murmur3_"):
                if candidate_text is None:
                    continue
                digest = fn(candidate_text)
            else:
                digest = fn(candidate_bytes)
        except Exception:
            continue
        m = match_digest(digest, target_str, target_kind, name, source="noncrypto")
        if m:
            return m
    return None

# ===================== External tools helpers =====================

def tool_exists(name: str) -> bool:
    return shutil.which(name) is not None

HC_MODE_RE = re.compile(r'^\s*(\d{1,5})\s*\|\s*([^|]+?)\s*\|')

def parse_hashcat_modes() -> Dict[str,str]:
    if not tool_exists("hashcat"):
        return {}
    try:
        r = subprocess.run(["hashcat", "-h"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        text = r.stdout
        modes = {}
        for line in text.splitlines():
            m = HC_MODE_RE.match(line)
            if m:
                mode, name = m.group(1), m.group(2).strip()
                modes[mode] = name
        if not modes:
            r2 = subprocess.run(["hashcat", "--example-hashes"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            for line in r2.stdout.splitlines():
                m2 = re.search(r'(?:MODE:\s*|Hash mode #)(\d+)', line)
                if m2:
                    modes.setdefault(m2.group(1), "unknown")
        return modes
    except Exception:
        return {}

# Return a mapping: hash -> {"plaintext": str, "modes": set([("m123","Name"), ...])}
def try_hashcat_all_modes_files_collect(wordlist_path: Path, hash_path: Path, verbose: bool=False) -> Dict[str, Dict[str, object]]:
    results: Dict[str, Dict[str, object]] = {}
    if not tool_exists("hashcat"):
        print("[external] Hashcat not found on PATH.")
        return results
    modes = parse_hashcat_modes()
    total = len(modes)
    if not modes:
        print("[external] Hashcat: no modes discovered.")
        return results

    print(f"[external] Hashcat detected. Modes available: {total}")
    print(f"[external] Hashcat: starting runs with wordlist={wordlist_path} hashes={hash_path}")
    sys.stdout.flush()

    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        out = td / "out.txt"
        if out.exists():
            out.unlink()
        for i, mode in enumerate(sorted(modes.keys(), key=lambda x: int(x)), start=1):
            try:
                if verbose or i == 1 or i % 50 == 0 or i == total:
                    print(f"[external] Hashcat: testing m{mode} - {modes.get(mode,'?')} ({i}/{total})")
                    sys.stdout.flush()
                cmd = [
                    "hashcat",
                    "-m", mode, "-a", "0",
                    "--quiet", "--potfile-disable",
                    "--outfile", str(out), "--outfile-format", "2",
                    str(hash_path), str(wordlist_path)
                ]
                subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

                if out.exists():
                    data = out.read_text(encoding="utf-8", errors="ignore")
                    if data.strip():
                        for line in data.splitlines():
                            if ":" not in line:
                                continue
                            h, plain = line.split(":", 1)
                            h = h.strip(); plain = plain.strip()
                            if not h or not plain:
                                continue
                            entry = results.setdefault(h, {"plaintext": plain, "modes": set()})
                            entry["modes"].add((f"m{mode}", modes.get(mode, "?")))
                    try:
                        out.write_text("", encoding="utf-8")
                    except Exception:
                        pass
            except Exception:
                continue
    return results

def parse_john_formats() -> List[str]:
    if not tool_exists("john"):
        return []
    fmts = set()
    try:
        r = subprocess.run(["john", "--list=format-details"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        text = r.stdout or ""
        for line in text.splitlines():
            m = re.match(r'^\s*([A-Za-z0-9_+.\-]+)\s', line)
            if m:
                fmts.add(m.group(1))
    except Exception:
        pass
    if not fmts:
        try:
            r2 = subprocess.run(["john", "--list=formats"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            t = (r2.stdout or "") + "\n" + (r2.stderr or "")
            m = re.search(r'Enabled formats:\s*(.*)', t, flags=re.IGNORECASE | re.DOTALL)
            block = m.group(1) if m else t
            tokens = re.findall(r'[A-Za-z0-9_+.\-]+', block)
            for tok in tokens:
                if tok.lower() in {"enabled","formats","format","cpu","opencl","ztex","cuda","list","help"}:
                    continue
                fmts.add(tok)
        except Exception:
            pass
    return sorted(fmts)

# Return a mapping: key -> {"plaintext": str, "formats": set([...])}
def try_john_all_formats_files_collect(wordlist_path: Path, hash_path: Path, fork: Optional[int], verbose: bool=False) -> Dict[str, Dict[str, object]]:
    results: Dict[str, Dict[str, object]] = {}
    if not tool_exists("john"):
        print("[external] John the Ripper not found on PATH.")
        return results
    formats = parse_john_formats()
    total = len(formats)
    if not formats:
        print("[external] John: no formats discovered.")
        return results

    print(f"[external] John the Ripper detected. Formats available: {total}")
    print(f"[external] John: starting runs with wordlist={wordlist_path} hashes={hash_path}")
    sys.stdout.flush()

    with tempfile.TemporaryDirectory() as td:
        potfile  = Path(td) / "john.pot"
        for i, fmt in enumerate(formats, start=1):
            try:
                if verbose or i == 1 or i % 50 == 0 or i == total:
                    print(f"[external] John: testing {fmt} ({i}/{total})")
                    sys.stdout.flush()
                cmd = ["john", f"--format={fmt}", f"--wordlist={wordlist_path}", f"--pot={potfile}", str(hash_path)]
                if fork and fork > 1:
                    cmd.insert(1, f"--fork={fork}")
                subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

                show = subprocess.run(
                    ["john", "--show", f"--format={fmt}", f"--pot={potfile}", str(hash_path)],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
                )
                out = (show.stdout or "").splitlines()

                for line in out:
                    if not line or "password hashes cracked" in line.lower():
                        continue
                    if ":" not in line:
                        continue
                    left, plaintext = line.rsplit(":", 1)
                    plaintext = plaintext.strip()
                    left = left.strip()
                    if not plaintext:
                        continue
                    entry = results.setdefault(left, {"plaintext": plaintext, "formats": set()})
                    entry["formats"].add(fmt)
            except Exception:
                continue
    return results

def find_line_number_in_file(path: Path, plaintext: str) -> Optional[int]:
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            for i, line in enumerate(f, start=1):
                if line.rstrip("\r\n") == plaintext:
                    return i
    except Exception:
        pass
    return None

# ===================== One-candidate matcher (local algorithms only) =====================

def first_match_for_value(candidate_bytes: bytes, candidate_text_or_none: Optional[str],
                          target_text: str, enable_noncrypto: bool) -> Tuple[Optional[str], int]:
    tested = 0
    target_kind = detect_target_format(target_text)
    target_str  = target_text.strip()
    tbytes = target_bytes_from_hex(target_str) if target_kind == 'hex' else target_bytes_from_b64(target_str)
    target_len_bytes = len(tbytes) if tbytes is not None else None

    tested += 1
    pl = try_passlib(candidate_text_or_none, target_str)
    if pl:
        return pl, tested

    for alg in algorithms_order():
        tested += 1
        m = try_hashlib_alg(alg, candidate_bytes, target_str, target_kind, target_len_bytes)
        if m:
            return m, tested

    for (name, func, varlen, src) in extra_algorithms():
        tested += 1
        m = try_extra_alg(name, func, candidate_bytes, target_str, target_kind, target_len_bytes, varlen, src)
        if m:
            return m, tested

    if enable_noncrypto:
        tested += 1
        m = try_noncrypto(candidate_bytes, candidate_text_or_none, target_str, target_kind)
        if m:
            return m, tested

    return None, tested

# ===================== Encoding detection & candidates =====================

def detect_text_encoding(b: bytes) -> Optional[str]:
    if b.startswith(b'\xff\xfe'): return 'utf-16-le'
    if b.startswith(b'\xfe\xff'): return 'utf-16-be'
    if b.startswith(b'\xef\xbb\xbf'): return 'utf-8-sig'
    sample = b[:4096]
    if b'\x00' in sample:
        even_zeros = sum(1 for i in range(0,len(sample),2) if sample[i]==0)
        odd_zeros  = sum(1 for i in range(1,len(sample),2) if sample[i]==0)
        if even_zeros > odd_zeros*2: return 'utf-16-be'
        if odd_zeros  > even_zeros*2: return 'utf-16-le'
    try:
        sample.decode('utf-8'); return 'utf-8'
    except Exception:
        return None

def build_candidates(value_file_bytes: bytes) -> List[Tuple[int, str, str, bytes, Optional[str]]]:
    enc = detect_text_encoding(value_file_bytes)
    candidates = []

    if enc:
        text = value_file_bytes.decode(enc, errors='strict')
        lines = text.splitlines()
        for idx, line in enumerate(lines, start=1):
            if line == "": continue
            bs_utf8 = line.encode('utf-8')
            candidates.append((idx, 'utf-8', line, bs_utf8, line))
            if enc not in ('utf-8','utf-8-sig'):
                bs_orig = line.encode(enc)
                if bs_orig != bs_utf8:
                    candidates.append((idx, enc, line, bs_orig, line))
    else:
        raw_lines = value_file_bytes.splitlines()
        if raw_lines and raw_lines[0].startswith(b'\xef\xbb\xbf'):
            raw_lines[0] = raw_lines[0][3:]
        for idx, ln in enumerate(raw_lines, start=1):
            if not ln: continue
            line_text = None
            try:
                line_text = ln.decode('utf-8', errors='strict')
                preview = line_text
            except Exception:
                preview = ln.decode('utf-8', errors='replace')
            candidates.append((idx, 'raw-bytes', preview, ln, line_text))

    seen = set(); uniq=[]
    for item in candidates:
        key = item[3]
        if key in seen: continue
        seen.add(key); uniq.append(item)
    return uniq

# ===================== I/O & CLI =====================

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Identify which hash matches a target (local algs; Hashcat ALL modes & John ALL formats with --try-external).")
    p.add_argument("--valueof",   type=Path, help="File with VALUEs (one per line) — will be used as wordlist for external tools.")
    p.add_argument("--hashvalue", type=Path, help="File with TARGET digest(s) — will be used as hash file for external tools.")
    p.add_argument("--value-file", type=Path, help="(Legacy) same as --valueof.")
    p.add_argument("--hash-file",  type=Path, help="(Legacy) same as --hashvalue.")
    p.add_argument("value", nargs='?', default="", help="(Legacy) single value as text.")
    p.add_argument("hash_value", nargs='?', default="", help="(Legacy) hash string.")
    p.add_argument("--try-external", action="store_true",
                   help="Try ALL Hashcat modes and ALL John formats using your files as wordlist/hashes.")
    p.add_argument("--external-verbose", action="store_true",
                   help="Print per-mode/per-format progress (very chatty).")
    p.add_argument("--john-fork", type=int, default=None,
                   help="Pass --fork N to John for parallelism.")
    p.add_argument("--no-noncrypto", action="store_true",
                   help="Disable non-crypto hashes (mmh3/xxhash). Enabled by default.")
    return p

def resolve_inputs(args):
    """
    Returns:
      (value_file_bytes, hash_text_or_single, mode_label, value_path_or_None, hash_path_or_None)
      - hash_text_or_single: if file mode -> full text of file (multiple lines), otherwise single string
    """
    if args.valueof or args.hashvalue:
        if not (args.valueof and args.hashvalue):
            raise SystemExit("Use BOTH --valueof and --hashvalue together.")
        vb = args.valueof.read_bytes()
        ht = args.hashvalue.read_text(encoding="utf-8", errors="strict")
        return vb, ht, "fileonly", args.valueof, args.hashvalue

    if args.value_file or args.hash_file:
        if not (args.value_file and args.hash_file):
            raise SystemExit("Use BOTH --value-file and --hash-file together.")
        vb = args.value_file.read_bytes()
        ht = args.hash_file.read_text(encoding="utf-8", errors="strict")
        return vb, ht, "legacy-files", args.value_file, args.hash_file

    if not (args.value and args.hash_value):
        raise SystemExit("No inputs provided. Use --valueof/--hashvalue or legacy flags/positionals.")
    return args.value.encode('utf-8'), args.hash_value, "positionals", None, None

def main() -> None:
    print("identify_hash.py v6.1 (local algs; Hashcat ALL modes & John ALL formats with --try-external) - multi-hash & multi-crack reporting")
    parser = build_parser(); args = parser.parse_args()
    value_file_bytes, hash_text_or_single, mode, value_path, hash_path = resolve_inputs(args)
    enable_noncrypto = not args.no_noncrypto

    if mode in ("fileonly", "legacy-files"):
        target_lines = [l.strip() for l in hash_text_or_single.splitlines() if l.strip()]
        if not target_lines:
            raise SystemExit("Hash file contained no non-empty lines.")
    else:
        target_lines = [hash_text_or_single.strip()]

    candidates = build_candidates(value_file_bytes)
    print(f"Candidates after encoding handling: {len(candidates)}")
    for i, (ln, enc_lbl, txt, bs, tx) in enumerate(candidates[:3], start=1):
        print(f"  [{i}] line={ln} enc={enc_lbl} len={len(bs)} preview={repr(txt[:80])}")
    if len(candidates) > 3:
        print(f"  ... ({len(candidates)-3} more)")
    if not candidates:
        raise SystemExit("No non-empty lines found in the value file.")

    overall_total_steps = 0
    any_local_matches = False

    for tidx, target_text in enumerate(target_lines, start=1):
        print("\n" + ("="*60))
        print(f"Processing target #{tidx}: {repr(target_text[:120])}")
        target_kind = detect_target_format(target_text)
        tbytes = target_bytes_from_hex(target_text) if target_kind == 'hex' else target_bytes_from_b64(target_text)
        target_len_bytes = len(tbytes) if tbytes is not None else None
        if target_len_bytes is not None:
            print(f"Target digest length: {target_len_bytes} bytes ({'hex' if target_kind=='hex' else 'base64'})")
        else:
            print("Target digest length: unknown (could not parse target fully)")

        matched_for_this_target = False
        steps_for_target = 0

        for line_no, enc_label, preview_text, cand_bytes, cand_text in candidates:
            m, steps = first_match_for_value(cand_bytes, cand_text, target_text, enable_noncrypto)
            steps_for_target += steps
            overall_total_steps += steps
            if m:
                any_local_matches = True
                matched_for_this_target = True
                print("\n=== MATCH FOUND (Local) ===")
                print(f"Target index              : {tidx}")
                print(f"Line number               : {line_no}")
                print(f"Encoding used for bytes   : {enc_label}")
                print(f"Candidate length          : {len(cand_bytes)} bytes")
                print("Matched value (verbatim bytes): ", end=""); sys.stdout.flush()
                sys.stdout.buffer.write(cand_bytes + b"\n")
                print(f"Matched value (utf8/escaped)  : {repr(preview_text)}")
                print(f"Matched value (hex)           : {binascii.hexlify(cand_bytes).decode('ascii')}")
                print(f"Matched algorithm             : {m}")
                print(f"Total local steps (this target): {steps_for_target}")
                break

        if not matched_for_this_target:
            print(f"\nNo local match found for target #{tidx} after {steps_for_target} local steps.")

    if args.try_external:
        if not (value_path and hash_path):
            print("[external] Skipping external tools: they require file-based inputs (--valueof/--hashvalue).")
        else:
            print(f"[external] Tools enabled. hashcat={'FOUND' if tool_exists('hashcat') else 'NOT FOUND'}, john={'FOUND' if tool_exists('john') else 'NOT FOUND'}")

            hc_results = try_hashcat_all_modes_files_collect(value_path, hash_path, verbose=args.external_verbose)
            jn_results = try_john_all_formats_files_collect(value_path, hash_path, fork=args.john_fork, verbose=args.external_verbose)

            if hc_results:
                print("\n=== EXTERNAL RESULTS: Hashcat (ALL cracks) ===")
                for h, info in hc_results.items():
                    plain = info["plaintext"]
                    modes = sorted(info["modes"])
                    ln = find_line_number_in_file(value_path, plain)
                    if ln:
                        print(f"- {h}\n    plaintext: {plain}  (known.txt line {ln})")
                    else:
                        print(f"- {h}\n    plaintext: {plain}")
                    for m_id, m_name in modes:
                        print(f"    via: {m_name} ({m_id})")

            if jn_results:
                print("\n=== EXTERNAL RESULTS: John the Ripper (ALL cracks) ===")
                for key, info in jn_results.items():
                    plain = info["plaintext"]
                    formats = sorted(info["formats"])
                    ln = find_line_number_in_file(value_path, plain)
                    print(f"- {key}")
                    if ln:
                        print(f"    plaintext: {plain}  (known.txt line {ln})")
                    else:
                        print(f"    plaintext: {plain}")
                    for fmt in formats:
                        tag = f"fork={args.john_fork}" if args.john_fork and args.john_fork > 1 else ""
                        print(f"    via: {fmt} {tag}".rstrip())

            if not hc_results and not jn_results:
                print("\n[external] No cracks found by Hashcat or John across all modes/formats.")

    print("\n" + ("="*60))
    if any_local_matches:
        print("Some targets were matched locally. See above per-target results.")
    else:
        print("No local matches found for any provided target hashes.")
    print(f"Total local steps tried across all targets: {overall_total_steps}")
    print("Tips:")
    print("  • External runs will only work if your hash file matches each tool’s expected format (salts/fields).")
    print("  • Use --external-verbose to print every mode/format as it tries.")
    print("  • Install extras for broader local coverage: pip install blake3 pycryptodome passlib[bcrypt,argon2] mmh3 xxhash.")
    print("  • Keccak != SHA3; some tools label Keccak as SHA3 incorrectly.")

if __name__ == "__main__":
    main()
