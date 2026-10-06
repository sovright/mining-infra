#!/usr/bin/env python3
"""Independent, stdlib-only transparent NU7 digest vectors, not valid spends.

Implements ZIP 244 T.1/T.2 and auth digests plus ZIP 229 empty v6 bundles.
Sources checked 2026-10-05: https://zips.z.cash/zip-0244 and /zip-0229.
No Rust code, node RPC, or zcash library is used to calculate expected values.
Run from any directory; stdout is the deterministic frozen JSON fixture.
"""
import hashlib
import json
import struct


def h(person, data=b""):
    return hashlib.blake2b(data, digest_size=32, person=person).digest()


def vector(version, branch, script):
    header = struct.pack("<IIIII", 0x80000000 | version,
                         0x26A7270A if version == 5 else 0xD884B698,
                         branch, 0, 4_465_100)
    outpoint = bytes(range(32)) + struct.pack("<I", 2)
    sequence = struct.pack("<I", 0xFFFFFFFE)
    # Small fixed scripts: their lengths fit one-byte CompactSize encodings.
    script_sig = bytes([len(script)]) + script
    output = struct.pack("<Q", 12_345) + b"\x01\x51"
    raw = header + b"\x01" + outpoint + script_sig + sequence + b"\x01" + output
    raw += b"\0" * (3 if version == 5 else 4)  # empty shielded bundles
    transparent = h(b"ZTxIdTranspaHash", h(b"ZTxIdPrevoutHash", outpoint)
                    + h(b"ZTxIdSequencHash", sequence) + h(b"ZTxIdOutputsHash", output))
    effects = h(b"ZTxIdHeadersHash", header) + transparent + h(b"ZTxIdSaplingHash")
    auth = h(b"ZTxAuthTransHash", script_sig)
    if version == 5:
        effects += h(b"ZTxIdOrchardHash")
        auth += h(b"ZTxAuthSapliHash") + h(b"ZTxAuthOrchaHash")
    else:
        effects += h(b"ZTxIdOrchardH_v6") + h(b"ZTxIdIronwd_H_v6")
        auth += h(b"ZTxAuthSapliH_v6") + h(b"ZTxAuthOrchaH_v6") + h(b"ZTxAuthIrnwdH_v6")
    branch_bytes = struct.pack("<I", branch)
    txid = h(b"ZcashTxHash_" + branch_bytes, effects)
    auth_digest = h(b"ZTxAuthHash_" + branch_bytes, auth)
    return dict(version=version, branch_id=f"{branch:08x}", script_sig=script.hex(),
                tx_hex=raw.hex(), txid_wire=txid.hex(), auth_wire=auth_digest.hex(),
                txid_display=txid[::-1].hex(), auth_display=auth_digest[::-1].hex())


if __name__ == "__main__":
    vectors = [vector(v, branch, script) for v in (5, 6)
               for branch in (0x77190AD9, 0x37A5165B) for script in (b"\x51", b"\x52\x53")]
    print(json.dumps({"scope": "Synthetic transparent-only digests; no UTXO, signature, or shielded validity claim",
                      "sources": ["https://zips.z.cash/zip-0244", "https://zips.z.cash/zip-0229"],
                      "vectors": vectors}, indent=2))
