# 2S-BBKPIR

This repository contains the 2S-BBKPIR protocol implementation: SHKR keyword filtering, Boolean MPC, standard three-copy PBC-DPF batch retrieval, dual FourQ OPRF, HKDF-SHA256, and AES-256-GCM. It contains no paper datasets, measured results, benchmark drivers, or VM-specific dependency builds.

## Requirements

- Linux x86-64 with AVX2; CMake 3.24+, a C++17 compiler, OpenMP, GNU gold, OpenSSL, Boost.System/Thread, GMP/GMPXX, and Python 3 with NumPy (only for generating the example corpus).
- A built [YACL](https://github.com/secretflow/yacl) tree with its Bazel `p2mpfq-2.params` link-parameter file. The tested YACL commit is `c7d00413e4578859c193389f8942e6cbe68b62e2`.
- An ABI-compatible existing C++ dependency build containing `libotextension.a`, `libencrypto_utils.a`, `librelic_s.a`, `libgmpxx.a`, `libgmp.a`, APSI headers, ENCRYPTO's generated `cmake_constants.h`, and the APSI compatibility headers. The setup helper accepts their installed prefix and source/build paths; it does not download or install anything.
- Source trees for [OTExtension](https://github.com/encryptogroup/OTExtension) (`2057fb0d4cfd39674e7813bc98d6d0a863138fc4`), [APSI](https://github.com/microsoft/APSI) (`b967a126b4e1c682b039afc2d76a98ea2c993230`), [dpf-cpp](https://github.com/dkales/dpf-cpp) (`14bafa285845d5c4e5ab28b030283258aad67e48`), [Microsoft GSL](https://github.com/microsoft/GSL) (`417ef685eafd626db765f0027b7fc5a0057e0770`), [yaml-cpp](https://github.com/jbeder/yaml-cpp) (`f7320141120f720aecc4c32be25586e7da9eb978`), and [nlohmann/json](https://github.com/nlohmann/json) (`9cca280a4d0ccf0c08f47a99aa71d1b0e52f8d03`). The matching ENCRYPTO_utils commit is `fd0efb26c28556ca9d6c1643bcbe2de7e070fefb`.
- A FourQ/APSI OPRF static archive containing the APSI `Item` and `ECPoint` objects and their FourQ dependencies. Pass its path with `--fourq-archive`.

The patches in `patches/` are required. Apply `dpf-fresh-randomness.patch` to the pinned dpf-cpp source and both `kk13-*.patch` files to the pinned OTExtension source before building. For example, from the repository root:

```bash
git -C /path/to/dpf-cpp apply --recount --unidiff-zero "$PWD/patches/dpf-fresh-randomness.patch"
git -C /path/to/OTExtension apply --recount --unidiff-zero "$PWD/patches/kk13-drain-response.patch"
git -C /path/to/OTExtension apply --recount --unidiff-zero "$PWD/patches/kk13-blocking-response.patch"
```

`dpf-cpp` must use fresh root randomness, and the patched KK13 receiver source must be the one passed to the build helper. Do not apply the patches twice. The required libraries are external to this repository; this is a source release, not a self-contained dependency bundle.

## Build

Use already-built dependencies. The setup helper only checks paths and writes local files under `build/`:

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

Run `python3 scripts/configure_dependencies.py --help` for overrides when APSI, the library prefix, generated ENCRYPTO headers, or YACL link params are elsewhere. The build produces `shkr_preprocess`, `shkr_node`, and the internal offline correctness verifier `shkr_verify`.

## Run a local example

The example generates a new synthetic corpus with `N=4096`, `M=128`, two AND predicates, and exactly eight matches. It does not use or contain any of the paper's measured data.

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
cat results/example/raw_runs.csv
```

The output row should report `correct=true` and `payload_result_valid=true`. To use another workload, provide a corpus in the same format as `scripts/generate_synthetic.py`, update `configs/example.yaml`, and run the same three roles. Each role is a separate process; preprocessing runs before online timing. The example uses fresh OT tokens and Beaver triples. Runtime-generated `build/`, `data/`, `artifacts/`, `results/`, and `tmp/` directories are ignored by Git.
