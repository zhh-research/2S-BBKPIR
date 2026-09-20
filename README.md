# 2S-BBKPIR

## Dependencies

- Linux x86-64 with AVX2; C++17 compiler, CMake ≥3.24, OpenMP, GNU gold, OpenSSL, Boost.System/Thread, GMP/GMPXX.
- Built YACL (including `p2mpfq-2.params`), OTExtension, ENCRYPTO_utils, RELIC, APSI/FourQ; a FourQ OPRF static archive for `--fourq-archive`.
- Source trees: [dpf-cpp](https://github.com/dkales/dpf-cpp), [OTExtension](https://github.com/encryptogroup/OTExtension), [GSL](https://github.com/microsoft/GSL), [yaml-cpp](https://github.com/jbeder/yaml-cpp), [nlohmann/json](https://github.com/nlohmann/json).
- Python 3 and NumPy for the example data generator.
- `--existing-cpp` must point to a compatible dependency build containing the OT/ENCRYPTO/RELIC/GMP libraries, APSI headers, and generated ENCRYPTO headers. Run `python3 scripts/configure_dependencies.py --help` if these paths differ.

Use dpf-cpp commit `14bafa285845d5c4e5ab28b030283258aad67e48` and OTExtension commit `2057fb0d4cfd39674e7813bc98d6d0a863138fc4`; apply the included patches once:

```bash
git -C /path/to/dpf-cpp apply --unidiff-zero "$PWD/patches/dpf-fresh-randomness.patch"
git -C /path/to/OTExtension apply --unidiff-zero "$PWD/patches/kk13-drain-response.patch"
git -C /path/to/OTExtension apply --unidiff-zero "$PWD/patches/kk13-blocking-response.patch"
```

## Build

```bash
python3 scripts/configure_dependencies.py \
  --existing-cpp /path/to/existing-cpp-build \
  --yacl-root /path/to/yacl \
  --dpf-source /path/to/patched/dpf-cpp \
  --ot-source /path/to/patched/OTExtension \
  --gsl-source /path/to/GSL \
  --yaml-source /path/to/yaml-cpp \
  --json-source /path/to/json \
  --fourq-archive /path/to/libshkr_fourq.a
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

## Test

```bash
python3 scripts/generate_synthetic.py \
  --N 4096 --M-real 128 --M 128 --k 2 --requested-t 8 \
  --entry-bytes 256 --output data/example
./build/shkr_preprocess --config configs/example.yaml
mkdir -p tmp
OMP_NUM_THREADS=4 ./build/shkr_node --role s0 --config configs/example.yaml >tmp/s0.log 2>&1 & s0=$!
OMP_NUM_THREADS=4 ./build/shkr_node --role s1 --config configs/example.yaml >tmp/s1.log 2>&1 & s1=$!
OMP_NUM_THREADS=4 ./build/shkr_node --role client --config configs/example.yaml >tmp/client.log 2>&1 & client=$!
wait "$client" && wait "$s0" && wait "$s1"
python3 -c 'import csv; r=next(csv.DictReader(open("results/example/raw_runs.csv"))); assert r["correct"] == "true" and r["payload_result_valid"] == "true" and r["matched_count"] == "8"; print("PASS")'
```
