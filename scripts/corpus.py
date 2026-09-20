import json
import struct
from pathlib import Path
import numpy as np


def dump(path, obj):
    Path(path).write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n")


def header(magic, n, m, count):
    return struct.pack("<8sIQIIIQQ", magic.encode(), 1, n, m, 1, m, count, (n + 63) // 64)


def write_corpus(out, bitmaps, n, mr, mapping, payloads, queries, extra):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    m = len(bitmaps)
    with (out / "bitmaps.bin").open("wb") as f:
        f.write(header("SHPRBMP1", n, m, m))
        for row in bitmaps:
            f.write(np.asarray(row, dtype="<u8").tobytes())
    with (out / "payload_plain.bin").open("wb") as f:
        f.write(header("SHPRPAY1", n, m, n))
        for payload in payloads:
            f.write(payload)
    dump(out / "row_mapping.json", mapping)
    dump(out / "queries.json", {"families": queries})
    manifest = {
        "dataset_id": out.name,
        "N": n,
        "M_real": mr,
        "M": m,
        "word_count": (n + 63) // 64,
        "version": 1,
        **extra,
    }
    dump(out / "manifest.json", manifest)
    dump(
        out / "records_meta.json",
        {
            "N": n,
            "record_index": "canonical shuffled zero-based offset",
            "bit_order": "little-endian; record n is bit n%64 of word n//64",
        },
    )


def count_and(bitmaps, rows):
    mask = np.bitwise_and.reduce(np.asarray([bitmaps[r] for r in rows]))
    return int(np.unpackbits(mask.view(np.uint8)).sum())


def flat_query(bitmaps, rows):
    return {
        "rows": rows,
        "formula": {"op": "AND", "children": list(range(len(rows)))},
        "plaintext_count": count_and(bitmaps, rows),
    }
