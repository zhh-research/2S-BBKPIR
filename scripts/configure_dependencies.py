#!/usr/bin/env python3

import argparse
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def existing(value, label, filename=None):
    if value is None:
        raise SystemExit(f"Missing {label}; see --help")
    path = Path(value).expanduser().resolve()
    required = path / filename if filename else path
    if not required.exists():
        raise SystemExit(f"Missing {label}: {required}")
    return path


def cmake_path(path):
    return str(path).replace("\\", "\\\\").replace('"', '\\"')


def main():
    parser = argparse.ArgumentParser(
        description="Reuse existing dependency builds without installing or modifying them."
    )
    parser.add_argument(
        "--existing-cpp", required=True, help="Existing ABY/ENCRYPTO/APSI build root"
    )
    parser.add_argument("--yacl-root", required=True)
    parser.add_argument("--yacl-params", help="YACL Bazel link .params file")
    parser.add_argument("--dpf-source", required=True, help="Patched dpf-cpp source")
    parser.add_argument("--ot-source", required=True, help="Patched OTExtension source")
    parser.add_argument("--gsl-source", required=True)
    parser.add_argument("--yaml-source", required=True)
    parser.add_argument("--json-source", required=True)
    parser.add_argument("--fourq-archive", required=True, help="Minimal APSI FourQ OPRF archive")
    parser.add_argument("--prefix", help="Installed OT/ENCRYPTO/RELIC/GMP prefix")
    parser.add_argument("--apsi-source")
    parser.add_argument("--compat-include")
    parser.add_argument("--encrypto-generated-include")
    args = parser.parse_args()

    cpp = existing(args.existing_cpp, "existing C++ build")
    yacl = existing(args.yacl_root, "YACL root")
    params = existing(
        args.yacl_params or yacl / "examples/bazel-bin/P2MPFQ/p2mpfq-2.params",
        "YACL link params",
    )
    prefix = existing(args.prefix or cpp / "local", "dependency prefix", "lib/libotextension.a")
    for archive in ("libencrypto_utils.a", "librelic_s.a", "libgmpxx.a", "libgmp.a"):
        existing(prefix / "lib" / archive, archive)
    sources = {
        "SHKR_DPF_SOURCE": existing(args.dpf_source, "dpf-cpp", "dpf.cpp"),
        "SHKR_OT_SOURCE": existing(args.ot_source, "OTExtension", "ot/kk-ot-ext-rec.cpp"),
        "SHKR_GSL_SOURCE": existing(args.gsl_source, "GSL", "include/gsl/gsl"),
        "SHKR_YAML_SOURCE": existing(args.yaml_source, "yaml-cpp", "CMakeLists.txt"),
        "SHKR_JSON_SOURCE": existing(
            args.json_source, "nlohmann/json", "single_include/nlohmann/json.hpp"
        ),
        "SHKR_APSI_SOURCE": existing(
            args.apsi_source or cpp / "third_party/APSI", "APSI", "common/apsi/item.h"
        ),
        "SHKR_COMPAT_INCLUDE": existing(
            args.compat_include or cpp / "src/third_party_compat",
            "APSI compatibility headers",
            "apsi/config.h",
        ),
        "SHKR_ENCRYPTO_GENERATED_INCLUDE": existing(
            args.encrypto_generated_include or cpp / "build/aby/extern/ENCRYPTO_utils/include",
            "ENCRYPTO generated headers",
            "cmake_constants.h",
        ),
        "SHKR_FOURQ_ARCHIVE": existing(args.fourq_archive, "FourQ archive"),
        "SHKR_PREFIX": prefix,
    }
    dpf_code = (sources["SHKR_DPF_SOURCE"] / "dpf.cpp").read_text()
    if "RAND_bytes(" not in dpf_code or "PRNG p(fresh)" not in dpf_code:
        raise SystemExit("dpf-cpp is missing patches/dpf-fresh-randomness.patch")
    receiver_code = (sources["SHKR_OT_SOURCE"] / "ot/kk-ot-ext-rec.cpp").read_text()
    if (
        "while(!(mask_queue.empty()))" not in receiver_code
        or "while(!(mask_queue->empty()))" not in receiver_code
        or "while(chan->data_available() && !(mask_queue->empty()))" in receiver_code
    ):
        raise SystemExit("OTExtension is missing the required KK13 receiver patches")

    execroot = (yacl / "examples/bazel-examples").resolve()
    existing(execroot, "YACL Bazel execroot")
    flags = []
    for line in params.read_text().splitlines()[2:]:
        if line.startswith(("-fuse-ld=", "-B")) or line == "-pass-exit-codes":
            continue
        if line.startswith("bazel-out/"):
            if "/P2MPFQ/" in line:
                continue
            line = str(execroot / line)
        if line.startswith("-Wl,"):
            flags.extend(line[4:].split(","))
        else:
            flags.append("-lpthread" if line == "-pthread" else line)

    includes = [yacl, execroot / "bazel-out/k8-fastbuild/bin/external/yacl~"]
    ext = execroot / "external"
    for package, subdir in (
        ("abseil-cpp~", ""),
        ("fmt~", "include"),
        ("spdlog~", "include"),
        ("brpc~", "src"),
        ("protobuf~", "src"),
        ("gflags~", "src"),
    ):
        includes.append(ext / package / subdir)
    includes.extend(
        (
            execroot / "bazel-out/k8-fastbuild/bin",
            execroot / "bazel-out/k8-fastbuild/bin/external/gflags~/_virtual_includes/gflags",
            execroot / "bazel-out/k8-fastbuild/bin/external/brpc~/src",
        )
    )
    generated = execroot / "bazel-out/k8-fastbuild/bin/external"
    for pattern in ("*/_virtual_includes/*", "*/src/_virtual_includes/*"):
        includes.extend(path for path in generated.glob(pattern) if path.is_dir())
    includes.append(execroot / "bazel-out/k8-fastbuild/bin/external/openssl~/openssl/include")
    includes = list(dict.fromkeys(path for path in includes if path.is_dir()))

    build = ROOT / "build"
    build.mkdir(exist_ok=True)
    rsp = build / "yacl_link.rsp"
    rsp.write_text("\n".join(flags) + "\n")
    sources["SHKR_YACL_RSP"] = rsp
    cmake = [f'set({name} "{cmake_path(path)}")' for name, path in sources.items()]
    cmake.append(
        "set(SHKR_YACL_INCLUDES " + " ".join(f'"{cmake_path(path)}"' for path in includes) + ")"
    )
    (build / "deps.cmake").write_text("\n".join(cmake) + "\n")
    print(f"Configured existing dependencies in {build}; no libraries were installed or changed.")


if __name__ == "__main__":
    main()
