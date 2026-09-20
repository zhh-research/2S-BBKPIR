#!/usr/bin/env python3

import argparse
import hashlib
import struct
from pathlib import Path

import numpy as np

from corpus import dump, flat_query, header, write_corpus


def legacy(a):

    W = (a.N + 63) // 64
    rows = []
    for r in range(a.M):
        rng = np.random.default_rng(np.random.SeedSequence([a.seed, r]))
        row = (
            rng.bit_generator.random_raw(W).astype("<u8")
            if r < a.M_real
            else np.zeros(W, dtype="<u8")
        )
        if r < a.M_real:
            row[0] |= np.uint64(1)
        if a.N % 64:
            row[-1] &= np.uint64((1 << (a.N % 64)) - 1)
        rows.append(row)
    ks = sorted(set([1, 2, 4, 6, 8, 10, a.k]))
    families = []
    for fid in range(min(10, a.M_real)):
        queries = {str(k): flat_query(rows, [(fid + i) % a.M_real for i in range(k)]) for k in ks}
        families.append({"query_id": fid, "seed_record": 0, "queries": queries})
    plen = a.entry_bytes - 28

    def payloads():
        for i in range(a.N):
            text = f"synthetic|record_id={i}|seed={a.seed}".encode()
            yield struct.pack("<Q", i) + text[: plen - 8].ljust(plen - 8, b"\0")

    mapping = [{"attribute": "synthetic", "value": str(i), "row_id": i} for i in range(a.M_real)]
    write_corpus(
        a.output,
        rows,
        a.N,
        a.M_real,
        mapping,
        payloads(),
        families,
        {
            "kind": "synthetic_legacy_regression",
            "seed": a.seed,
            "entry_bytes": a.entry_bytes,
            "master_pool": "SeedSequence(seed,row_id), row prefixes stable",
        },
    )
    dump(str(Path(a.output) / "domains.json"), {"synthetic": [str(i) for i in range(a.M_real)]})


def exact_t(a):
    if a.attributes != 16:
        raise ValueError("frozen benchmark requires A=16")
    if a.M_real != a.M or a.M % a.attributes:
        raise ValueError("exact-t benchmark requires M_real=M and D=M/16")
    D = a.M // a.attributes
    if D < 2 or not 1 <= a.k <= a.attributes or not 1 <= a.requested_t <= a.N:
        raise ValueError("invalid exact-t dimensions")
    out = Path(a.output)
    out.mkdir(parents=True, exist_ok=True)
    W = (a.N + 63) // 64
    bitmap_path = out / "bitmaps.bin"
    with bitmap_path.open("wb") as f:
        f.write(header("SHPRBMP1", a.N, a.M, a.M))
        f.truncate(48 + a.M * W * 8)
    bitmap = np.memmap(bitmap_path, dtype="<u8", mode="r+", offset=48, shape=(a.M, W))
    records = np.arange(a.N, dtype=np.int64)
    words = records >> 6
    masks = np.left_shift(np.uint64(1), (records & 63).astype(np.uint64))
    outside = records[a.requested_t :]
    for attr in range(a.attributes):
        rng = np.random.default_rng(
            np.random.SeedSequence([a.seed, attr, a.N, a.M, a.k, a.requested_t])
        )
        values = rng.integers(0, D, size=a.N, dtype=np.int64)
        if attr < a.k:
            values[: a.requested_t] = 0
            breaker = outside[outside % a.k == attr]
            values[breaker] = 1
        rows = attr * D + values
        np.bitwise_or.at(bitmap, (rows, words), masks)
    bitmap.flush()
    query_rows = [attr * D for attr in range(a.k)]
    selected = np.asarray(bitmap[query_rows[0]]).copy()
    for row in query_rows[1:]:
        selected &= bitmap[row]
    actual = np.flatnonzero(np.unpackbits(selected.view(np.uint8), bitorder="little")[: a.N])
    intended = np.arange(a.requested_t, dtype=np.int64)
    if not np.array_equal(actual, intended):
        raise RuntimeError(
            f"exact-t reference failed: requested={a.requested_t} actual={len(actual)}"
        )
    intended_wire = b"".join(struct.pack("<Q", int(x)) for x in intended)
    intended_hash = hashlib.sha256(intended_wire).hexdigest()
    del bitmap
    plen = a.entry_bytes - 28
    with (out / "payload_plain.bin").open("wb") as f:
        f.write(header("SHPRPAY1", a.N, a.M, a.N))
        for i in range(a.N):
            text = f"exact-t|record_id={i}|seed={a.seed}".encode()
            f.write(struct.pack("<Q", i) + text[: plen - 8].ljust(plen - 8, b"\0"))
    mapping = [
        {"attribute": f"A{attr}", "value": str(value), "row_id": attr * D + value}
        for attr in range(a.attributes)
        for value in range(D)
    ]
    formula = {"op": "AND", "children": list(range(a.k))} if a.k > 1 else 0
    query = {
        "rows": query_rows,
        "formula": formula,
        "plaintext_count": a.requested_t,
        "requested_t": a.requested_t,
        "intended_I_sha256": intended_hash,
    }
    dump(
        out / "queries.json",
        {"families": [{"query_id": 0, "seed_record": 0, "queries": {str(a.k): query}}]},
    )
    dump(out / "row_mapping.json", mapping)
    dump(
        out / "domains.json",
        {f"A{attr}": [str(x) for x in range(D)] for attr in range(a.attributes)},
    )
    dump(
        out / "manifest.json",
        {
            "dataset_id": out.name,
            "N": a.N,
            "M_real": a.M,
            "M": a.M,
            "word_count": W,
            "version": 2,
            "kind": "synthetic_exact_t",
            "seed": a.seed,
            "entry_bytes": a.entry_bytes,
            "num_attributes": a.attributes,
            "categories_per_attribute": D,
            "requested_t": a.requested_t,
            "actual_t": int(len(actual)),
            "k": a.k,
            "intended_I_sha256": intended_hash,
            "construction": "first t records match; every other record has deterministic breaker_attr=n mod k set to value 1",
        },
    )
    dump(
        out / "records_meta.json",
        {
            "N": a.N,
            "record_index": "zero-based offset",
            "bit_order": "little-endian",
            "intended_I": {
                "first": 0,
                "last": a.requested_t - 1,
                "count": a.requested_t,
                "sha256_u64le": intended_hash,
            },
        },
    )


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--N", type=int, default=4096)
    p.add_argument("--M-real", type=int, default=16)
    p.add_argument("--M", type=int, default=16)
    p.add_argument("--k", type=int, default=4)
    p.add_argument("--seed", type=int, default=20260831)
    p.add_argument("--entry-bytes", type=int, default=256)
    p.add_argument("--output", default="data/synthetic")
    p.add_argument("--attributes", type=int, default=16)
    p.add_argument("--requested-t", type=int)
    a = p.parse_args()
    if not (0 < a.M_real <= a.M and a.N > 0 and a.entry_bytes >= 36 and a.k > 0):
        p.error("invalid corpus dimensions")
    try:
        exact_t(a) if a.requested_t is not None else legacy(a)
    except (ValueError, RuntimeError) as e:
        p.error(str(e))
    print(
        f'Generated {a.output}: kind={"exact-t" if a.requested_t is not None else "legacy"} N={a.N} M={a.M} k={a.k} t={a.requested_t}'
    )


if __name__ == "__main__":
    main()
