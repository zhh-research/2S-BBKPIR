#pragma once
#include "common/core.h"
#include "mpc/circuit.h"
#include <yaml-cpp/yaml.h>
namespace shks {
inline Json yaml_json(const YAML::Node &n) {
    if (n.IsNull())
        return nullptr;
    if (n.IsSequence()) {
        Json a = Json::array();
        for (auto x : n)
            a.push_back(yaml_json(x));
        return a;
    }
    if (n.IsMap()) {
        Json o = Json::object();
        for (auto x : n)
            o[x.first.as<std::string>()] = yaml_json(x.second);
        return o;
    }
    auto s = n.Scalar();
    if (s == "true")
        return true;
    if (s == "false")
        return false;
    try {
        size_t used = 0;
        auto v = std::stoll(s, &used);
        if (used == s.size())
            return v;
    } catch (...) {
    }
    try {
        size_t used = 0;
        auto v = std::stod(s, &used);
        if (used == s.size())
            return v;
    } catch (...) {
    }
    return s;
}
inline std::string pointer_path(std::string p) {
    std::replace(p.begin(), p.end(), '.', '/');
    return "/" + p;
}
struct Config {
    Json j, manifest;
    uint64_t N, W, epoch, layout_seed, pbc_profile_base, requested_t;
    uint32_t M, Mr, p, L, entry, pbc_slack_bits, A, D;
    size_t tokens, triples;
    bool reuse_tokens, reuse_triples, payload, paper_mode, benchmark_reuse_mode, require_exact_t;
    int warmup, repetitions, k, query_id;
    std::string role = "", dataset_id;
    fs::path corpus, common, artifacts;
    std::vector<std::string> addresses;
    template <class T> T get(const std::string &path, T fallback) const {
        auto ptr = Json::json_pointer(pointer_path(path));
        return j.contains(ptr) ? j.at(ptr).get<T>() : fallback;
    }
    Config(int argc, char **argv) {
        std::string path = "configs/benchmark_default.yaml";
        for (int i = 1; i < argc; i++)
            if (std::string(argv[i]) == "--config" && i + 1 < argc)
                path = argv[++i];
        j = yaml_json(YAML::LoadFile(path));
        for (int i = 1; i < argc; i++) {
            std::string a = argv[i];
            if (a == "--config") {
                i++;
                continue;
            }
            if (a == "--role") {
                require(i + 1 < argc, "missing role");
                role = argv[++i];
                continue;
            }
            if (a == "--set") {
                require(i + 1 < argc, "missing --set value");
                std::string v = argv[++i];
                auto eq = v.find('=');
                require(eq != std::string::npos, "override requires path=value");
                auto key = v.substr(0, eq);
                require(key != "index.real_rows" && key != "dataset.M_real",
                        "M_real comes from corpus");
                j[Json::json_pointer(pointer_path(key))] = yaml_json(YAML::Load(v.substr(eq + 1)));
            } else
                throw std::runtime_error("unknown argument: " + a);
        }
        corpus = get<std::string>("dataset.root", "data/synthetic");
        manifest = read_json(corpus / "manifest.json");
        dataset_id = get<std::string>("dataset.id", manifest.at("dataset_id").get<std::string>());
        require(dataset_id.find('/') == std::string::npos &&
                    dataset_id.find("..") == std::string::npos,
                "invalid dataset id");
        N = get<uint64_t>("dataset.record_count", manifest.at("N").get<uint64_t>());
        require(N > 0 && N <= manifest.at("N").get<uint64_t>(), "N exceeds corpus");
        W = word_count(N);
        Mr = manifest.at("M_real");
        p = get<uint32_t>("shks.partitions", 8);
        require(pow2(p) && p >= 2 && p <= 256, "native KK13 requires power-of-two p in [2,256]");
        auto ptr = Json::json_pointer("/index/padded_rows");
        if (!j.contains(ptr) || j.at(ptr) == "auto")
            M = next_pow2(std::max(Mr, p));
        else
            M = j.at(ptr).get<uint32_t>();
        require(M >= Mr && M % p == 0 && pow2(M / p), "require M_real<=M, p|M, power-of-two L");
        L = M / p;
        epoch = get<uint64_t>("preprocessing.epoch", 1);
        tokens =
            get<size_t>("shks.token_pool_size", get<size_t>("preprocessing.token_pool_size", 128));
        reuse_tokens =
            get<bool>("shks.reuse_tokens", get<bool>("preprocessing.reuse_tokens", true));
        triples = get<size_t>("preprocessing.triple_pool_size", 64);
        reuse_triples = get<bool>("preprocessing.reuse_triples", true);
        payload = get<bool>("payload.enabled", true);
        entry = get<uint32_t>("payload.entry_bytes", 256);
        auto corpus_entry = manifest.at("entry_bytes").get<uint32_t>();
        require(entry >= 36 && entry % 8 == 0 && entry == corpus_entry,
                "payload entry size must match corpus, be >=36 and word aligned");
        layout_seed = get<uint64_t>("payload.pbc.layout_seed", 20260901);
        require(get<uint32_t>("payload.pbc.width", 3) == 3, "PBC width is fixed at 3");
        pbc_slack_bits = get<uint32_t>("payload.pbc.zero_layout.slack_bits", 5);
        pbc_profile_base = get<uint64_t>("payload.pbc.zero_layout.profile_base",
                                         3 * (uint64_t(1) << pbc_slack_bits) + 1);
        if (payload)
            require(pow2(N), "Standard PBC payload retrieval requires power-of-two N");
        warmup = get<int>("benchmark.warmup", 3);
        repetitions = get<int>("benchmark.repetitions", 10);
        paper_mode = get<bool>("benchmark.paper_mode", false);
        benchmark_reuse_mode = get<bool>("benchmark.token_reuse_mode", false);
        require(warmup >= 0 && repetitions > 0, "invalid repetition count");
        if (paper_mode)
            require(!reuse_tokens && !reuse_triples,
                    "paper_mode requires fresh token and triple pools");
        require((!reuse_tokens && !reuse_triples) || benchmark_reuse_mode,
                "token/triple reuse requires explicit benchmark.token_reuse_mode=true");
        k = get<int>("query.leaf_count", 6);
        query_id = get<int>("query.query_id", 0);
        require(k > 0, "k must be positive");
        A = manifest.value("num_attributes", get<uint32_t>("benchmark.num_attributes", 0));
        D = manifest.value("categories_per_attribute",
                           get<uint32_t>("benchmark.categories_per_attribute", 0));
        requested_t =
            get<uint64_t>("benchmark.requested_t", manifest.value("requested_t", uint64_t(0)));
        require_exact_t = get<bool>("benchmark.require_exact_t", false);
        if (require_exact_t) {
            require(manifest.value("kind", std::string()) == "synthetic_exact_t",
                    "formal benchmark requires exact-t corpus");
            require(A == 16 && M == Mr && M % 16 == 0 && D == M / 16,
                    "formal exact-t corpus requires A=16 and D=M/16");
            require(requested_t > 0 && manifest.value("actual_t", uint64_t(0)) == requested_t,
                    "formal exact-t corpus cardinality mismatch");
            require(manifest.value("k", 0) == k, "formal exact-t corpus k mismatch");
        }
        common = fs::path("artifacts") / dataset_id / "common_standard_pbc_v3" /
                 ("N" + std::to_string(N)) /
                 ("M" + std::to_string(M) + "_epoch" + std::to_string(epoch) + "_entry" +
                  std::to_string(entry) + "_payload" + std::to_string(payload) + "_seed" +
                  std::to_string(layout_seed));
        artifacts =
            fs::path("artifacts") / dataset_id / "shks" /
            ("N" + std::to_string(N) + "_M" + std::to_string(M) + "_p" + std::to_string(p)) /
            ("tokens" + std::to_string(tokens) + "_triples" + std::to_string(triples) + "_epoch" +
             std::to_string(epoch) + "_host_" + get<std::string>("shks.host_mode", "alternate"));
        addresses = {get<std::string>("network.client_addr", "127.0.0.1:9300"),
                     get<std::string>("network.s0_addr", "127.0.0.1:9301"),
                     get<std::string>("network.s1_addr", "127.0.0.1:9302")};
    }
    Header header(uint64_t count) const {
        return {N, M, p, L, count, W};
    }
    Header common_header(uint64_t count) const {
        return {N, M, 1, M, count, W};
    }
    int threads(const std::string &r) const {
        int t = get<int>("threads." + r, 1);
        require(t > 0, "thread count must be positive");
        return t;
    }
    void validate_pool(const Circuit &c) const {
        require(c.leaves.size() == size_t(k),
                "leaf_count must equal syntactic leaf occurrences in formula");
        auto rt = size_t(reuse_tokens ? 1 : warmup + repetitions) * c.leaves.size();
        auto rb = size_t(reuse_triples ? 1 : warmup + repetitions) * c.triples;
        require(tokens >= rt, "token pool insufficient: required=" + std::to_string(rt) +
                                  " available=" + std::to_string(tokens));
        require(triples >= rb, "triple pool insufficient: required=" + std::to_string(rb) +
                                   " available=" + std::to_string(triples));
    }
};
struct Workload {
    Json ast;
    std::vector<uint32_t> rows;
};
inline Workload workload(const Config &c) {
    auto qpath = c.get<std::string>("query.formula_source", "queries.json");
    auto q = read_json(c.corpus / qpath);
    auto families = q.at("families");
    require(c.query_id >= 0 && size_t(c.query_id) < families.size(), "invalid query_id");
    auto family = families.at(c.query_id);
    Workload w;
    auto key = std::to_string(c.k);
    require(family.at("queries").contains(key),
            "query leaf_count absent from corpus; regenerate with requested k");
    auto query = family.at("queries").at(key);
    w.rows = query.at("rows").get<std::vector<uint32_t>>();
    w.ast = query.at("formula");
    auto ptr = Json::json_pointer("/query/formula");
    if (c.j.contains(ptr))
        w.ast = c.j.at(ptr);
    for (auto r : w.rows)
        require(r < c.Mr, "query references padding row");
    Circuit circuit(w.ast);
    for (auto i : circuit.leaves)
        require(size_t(i) < w.rows.size(), "formula leaf out of range");
    c.validate_pool(circuit);
    if (c.require_exact_t)
        require(query.at("plaintext_count").get<uint64_t>() == c.requested_t,
                "query plaintext_count differs from requested_t");
    return w;
}
inline std::vector<Words> load_plain_rows(const Config &c, const std::vector<uint32_t> &rows) {
    std::ifstream f(c.corpus / "bitmaps.bin", std::ios::binary);
    Bytes b(48);
    f.read((char *)b.data(), 48);
    auto h = Header::decode(b, "SHPRBMP1");
    require(h.N == c.manifest.at("N").get<uint64_t>() && h.M >= c.Mr && h.W == word_count(h.N) &&
                h.count == h.M,
            "corpus header mismatch");
    require(fs::file_size(c.corpus / "bitmaps.bin") == 48 + h.M * h.W * 8,
            "corpus bitmap size mismatch");
    std::vector<Words> out;
    for (auto r : rows) {
        require(r < h.M, "corpus row out of bounds");
        Words a(c.W);
        f.seekg(48 + uint64_t(r) * h.W * 8);
        f.read((char *)a.data(), c.W * 8);
        require(bool(f), "corpus read failed");
        mask_tail(a, c.N);
        out.push_back(std::move(a));
    }
    return out;
}
}
