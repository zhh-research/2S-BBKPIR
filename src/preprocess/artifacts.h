#pragma once
#include "common/config.h"
#include "crypto/oprf.h"
#include "payload/dpf_pbc.h"
#include <numeric>
#include <omp.h>
namespace shkr {
struct Token {
    uint32_t host = 0;
    std::vector<uint32_t> delta;
    Seed seed{};
    Words c;
};
struct ServerData {
    Words shares, triples, pbc_database;
    std::vector<Token> tokens;
    std::unique_ptr<OprfKey> key;
};
inline Json expected_manifest(const Config &c) {
    return {{"N", c.N},
            {"M_real", c.Mr},
            {"M", c.M},
            {"p", c.p},
            {"L", c.L},
            {"epoch", c.epoch},
            {"token_count", c.tokens},
            {"triple_count", c.triples},
            {"host_mode", c.get<std::string>("shkr.host_mode", "alternate")},
            {"corpus", fs::absolute(c.corpus).string()}};
}
inline Json common_manifest(const Config &c) {
    return {{"N", c.N},
            {"M_real", c.Mr},
            {"M", c.M},
            {"epoch", c.epoch},
            {"entry_bytes", c.entry},
            {"payload", c.payload},
            {"payload_backend", "static_standard_3copy_pbc_dpf_v3"},
            {"pbc_variant", "standard"},
            {"pbc_width", 3},
            {"physical_slots", 3 * c.N},
            {"layout_seed", c.layout_seed},
            {"corpus", fs::absolute(c.corpus).string()}};
}
inline bool cache_valid(const Config &c) {
    if (!fs::exists(c.artifacts / "manifest.json") || !fs::exists(c.common / "manifest.json"))
        return false;
    return read_json(c.artifacts / "manifest.json") == expected_manifest(c) &&
           read_json(c.common / "manifest.json") == common_manifest(c);
}
inline void save_tokens(const Config &c, const std::vector<Token> &tokens, int role) {
    Writer w;
    for (const auto &t : tokens) {
        w.u32(t.host);
        if (role == 0) {
            for (auto d : t.delta)
                w.u32(d);
        } else if (t.host == uint32_t(role - 1))
            w.raw(t.c.data(), t.c.size() * 8);
        else
            w.raw(t.seed.data(), 16);
    }
    std::string name = role == 0 ? "client" : "s" + std::to_string(role - 1);
    save_binary(c.artifacts / (name + "_tokens.bin"), c.header(c.tokens), "SHPRTOK1", w.b.data(),
                w.b.size());
}
inline std::vector<Token> load_tokens(const Config &c, int role) {
    auto hostmode = c.get<std::string>("shkr.host_mode", "alternate");
    require(hostmode == "alternate" || hostmode == "s0" || hostmode == "s1", "unknown host_mode");
    auto host = [&](size_t i) {
        return hostmode == "alternate" ? uint32_t(i % 2) : uint32_t(hostmode == "s1");
    };
    size_t size = 0;
    for (size_t i = 0; i < c.tokens; i++)
        size += 4 + (role == 0 ? c.p * 4 : (host(i) == uint32_t(role - 1) ? c.L * c.W * 8 : 16));
    std::string name = role == 0 ? "client" : "s" + std::to_string(role - 1);
    auto b =
        load_binary(c.artifacts / (name + "_tokens.bin"), c.header(c.tokens), "SHPRTOK1", size);
    Reader r(b);
    std::vector<Token> out(c.tokens);
    for (auto &t : out) {
        t.host = r.u32();
        require(t.host <= 1, "bad token host");
        if (role == 0) {
            t.delta.resize(c.p);
            for (auto &d : t.delta) {
                d = r.u32();
                require(d < c.L, "bad token shift");
            }
        } else if (t.host == uint32_t(role - 1)) {
            t.c.resize(c.L * c.W);
            r.raw(t.c.data(), t.c.size() * 8);
        } else
            r.raw(t.seed.data(), 16);
    }
    r.end();
    return out;
}
inline void preprocess(const Config &c) {
    auto w = workload(c);
    Circuit circuit(w.ast);
    c.validate_pool(circuit);
    if (cache_valid(c)) {
        std::cout << "Reusing matching offline artifact manifests\n";
        return;
    }
    bool reuse_common = fs::exists(c.common / "manifest.json");
    if (reuse_common)
        require(read_json(c.common / "manifest.json") == common_manifest(c),
                "common artifact manifest mismatch; choose another dataset.id");
    if (fs::exists(c.artifacts / "manifest.json"))
        require(read_json(c.artifacts / "manifest.json") == expected_manifest(c),
                "SHKR artifact manifest mismatch");
    omp_set_dynamic(0);
    omp_set_nested(0);
    omp_set_num_threads(c.get<int>("preprocessing.threads", 8));
    std::vector<uint32_t> r(c.Mr);
    std::iota(r.begin(), r.end(), 0);
    auto plain = load_plain_rows(c, r);
    while (plain.size() < c.M)
        plain.emplace_back(c.W, 0);
    if (!reuse_common) {
        Words s0(c.M * c.W), s1(c.M * c.W);
#pragma omp parallel for schedule(static)
        for (uint32_t row = 0; row < c.M; row++) {
            random_bytes(s0.data() + row * c.W, c.W * 8);
            s0[(row + 1) * c.W - 1] &= tail_mask(c.N);
            for (size_t word = 0; word < c.W; word++)
                s1[row * c.W + word] = s0[row * c.W + word] ^ plain[row][word];
        }
        save_binary(c.common / "s0_bitmap_shares.bin", c.common_header(c.M), "SHPRSHR1", s0.data(),
                    s0.size() * 8);
        save_binary(c.common / "s1_bitmap_shares.bin", c.common_header(c.M), "SHPRSHR1", s1.data(),
                    s1.size() * 8);
    }
    std::vector<Token> tokens(c.tokens);
    auto hostmode = c.get<std::string>("shkr.host_mode", "alternate");
    require(hostmode == "alternate" || hostmode == "s0" || hostmode == "s1", "unknown host mode");
#pragma omp parallel for schedule(static)
    for (size_t nu = 0; nu < c.tokens; nu++) {
        auto &t = tokens[nu];
        t.host = hostmode == "alternate" ? nu % 2 : hostmode == "s1";
        t.delta.resize(c.p);
        random_bytes(t.delta.data(), c.p * 4);
        for (auto &d : t.delta)
            d &= c.L - 1;
        t.seed = random_seed();
        t.c.resize(c.L * c.W);
        for (uint32_t j = 0; j < c.L; j++) {
            auto mask = prg(t.seed, hint_context(c.epoch, nu, j), c.N);
            for (size_t word = 0; word < c.W; word++) {
                uint64_t v = mask[word];
                for (uint32_t s = 0; s < c.p; s++)
                    v ^= plain[s * c.L + (j ^ t.delta[s])][word];
                t.c[j * c.W + word] = v;
            }
        }
    }
    for (int role = 0; role < 3; role++)
        save_tokens(c, tokens, role);
    tokens.clear();
    plain.clear();
    Words t0(c.triples * 3 * c.W), t1(c.triples * 3 * c.W);
#pragma omp parallel for schedule(static)
    for (size_t t = 0; t < c.triples; t++) {
        auto a = random_words(c.N), b = random_words(c.N), a0 = random_words(c.N),
             b0 = random_words(c.N), c0 = random_words(c.N);
        for (size_t i = 0; i < c.W; i++) {
            auto off = t * 3 * c.W;
            t0[off + i] = a0[i];
            t0[off + c.W + i] = b0[i];
            t0[off + 2 * c.W + i] = c0[i];
            t1[off + i] = a[i] ^ a0[i];
            t1[off + c.W + i] = b[i] ^ b0[i];
            t1[off + 2 * c.W + i] = (a[i] & b[i]) ^ c0[i];
        }
    }
    save_binary(c.artifacts / "s0_triples.bin", c.header(c.triples), "SHPRTRP1", t0.data(),
                t0.size() * 8);
    save_binary(c.artifacts / "s1_triples.bin", c.header(c.triples), "SHPRTRP1", t1.data(),
                t1.size() * 8);
    t0.clear();
    t1.clear();
    if (c.payload && !reuse_common) {
        oprf_consistency_test();
        OprfKey k0, k1;
        for (int b = 0; b < 2; b++) {
            auto &key = b == 0 ? k0 : k1;
            std::ostringstream s(std::ios::binary);
            key.save(s);
            auto raw = s.str();
            save_binary(c.common / ("s" + std::to_string(b) + "_oprf.key"), c.common_header(1),
                        "SHPRKEY1", raw.data(), raw.size());
        }
        std::ifstream input(c.corpus / "payload_plain.bin", std::ios::binary);
        require(bool(input), "missing corpus payload");
        Bytes head(48);
        input.read((char *)head.data(), 48);
        auto h = Header::decode(head, "SHPRPAY1");
        require(h.N >= c.N, "payload corpus too short");
        Bytes plainbytes(c.N * (c.entry - 28));
        input.read((char *)plainbytes.data(), plainbytes.size());
        require(bool(input), "payload file truncated");
        Bytes encrypted(c.N * c.entry);
#pragma omp parallel for schedule(static)
        for (uint64_t n = 0; n < c.N; n++) {
            auto z0 = direct_oprf(k0, c.epoch, n), z1 = direct_oprf(k1, c.epoch, n);
            auto entry =
                encrypt_payload(payload_key(z0, z1, c.epoch, n),
                                plainbytes.data() + n * (c.entry - 28), c.entry - 28, c.epoch, n);
            memcpy(encrypted.data() + n * c.entry, entry.data(), c.entry);
        }
        save_binary(c.common / "payload_logical.enc", c.common_header(c.N), "SHPRENC1",
                    encrypted.data(), encrypted.size());
        auto layout = make_pbc_layout(c.N, c.entry, c.layout_seed, encrypted);
        save_binary(c.common / "pbc_ranks_standard_v3.bin", c.common_header(3 * c.N), "SHPRPBS3",
                    layout.ranks.data(), layout.ranks.size() * sizeof(layout.ranks[0]));
        save_binary(c.common / "payload_pbc_standard_3x_v3.enc", c.common_header(3 * c.N),
                    "SHPRDBS3", layout.expanded.data(), layout.expanded.size());
        write_json(c.common / "pbc_manifest_standard_v3.json", pbc_manifest_standard_v3(c));
    }
    write_json(c.artifacts / "manifest.json", expected_manifest(c));
    write_json(c.common / "manifest.json", common_manifest(c));
    std::cout << "Offline preprocessing complete: " << c.artifacts << '\n';
}
inline ServerData load_server(const Config &c, int b) {
    require(cache_valid(c), "missing or incompatible offline artifacts");
    ServerData d;
    auto prefix = "s" + std::to_string(b);
    auto share = load_binary(c.common / (prefix + "_bitmap_shares.bin"), c.common_header(c.M),
                             "SHPRSHR1", c.M * c.W * 8);
    d.shares = words(share, c.M * c.W);
    share.clear();
    auto triples = load_binary(c.artifacts / (prefix + "_triples.bin"), c.header(c.triples),
                               "SHPRTRP1", c.triples * 3 * c.W * 8);
    d.triples = words(triples, c.triples * 3 * c.W);
    d.tokens = load_tokens(c, b + 1);
    if (c.payload) {
        validate_pbc_manifest_standard_v3(c);
        d.key = std::make_unique<OprfKey>();
        auto path = c.common / (prefix + "_oprf.key");
        auto keybytes = load_binary(path, c.common_header(1), "SHPRKEY1", OprfKey::key_size);
        std::istringstream s(std::string((const char *)keybytes.data(), keybytes.size()),
                             std::ios::binary);
        d.key->load(s);
        auto db = load_binary(c.common / "payload_pbc_standard_3x_v3.enc", c.common_header(3 * c.N),
                              "SHPRDBS3", 3 * c.N * c.entry);
        d.pbc_database = words(db, db.size() / 8);
    }
    return d;
}
}
