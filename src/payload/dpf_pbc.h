#pragma once
#include "common/config.h"
#include "network/link.h"
#include "payload/dpf_api.h"
#include <cmath>
#include <future>
#include <limits>
#include <numeric>
#include <omp.h>
namespace shks {

struct PbcLayout {
    std::vector<std::array<uint32_t, 3>> ranks;
    Bytes expanded;
};
inline PbcLayout make_pbc_layout(uint64_t N, uint32_t entry, uint64_t seed_value,
                                 const Bytes &logical) {
    require(pow2(N) && logical.size() == N * entry && 3 * N <= uint64_t(UINT32_MAX),
            "Standard PBC layout dimensions");
    Seed seed{};
    for (int i = 0; i < 8; i++)
        seed[i] = uint8_t(seed_value >> (8 * i));
    for (int i = 0; i < 8; i++)
        seed[8 + i] = uint8_t(0x5354445042435633ULL >> (8 * i));
    Writer domain;
    domain.text("STANDARD-PBC-V3-FISHER-YATES");
    auto stream = prg(seed, domain.b, 6 * N * 64);
    size_t cursor = 0;
    std::vector<uint32_t> pi(3 * N);
    std::iota(pi.begin(), pi.end(), 0);
    for (uint64_t i = 3 * N - 1; i > 0; i--) {
        uint64_t range = i + 1, threshold = (-range) % range, value;
        do {
            require(cursor < stream.size(), "PBC permutation entropy exhausted");
            value = stream[cursor++];
        } while (value < threshold);
        std::swap(pi[i], pi[value % range]);
    }
    PbcLayout out;
    out.ranks.resize(N);
    out.expanded.resize(3 * N * entry);
    for (uint64_t n = 0; n < N; n++)
        for (uint32_t copy = 0; copy < 3; copy++) {
            auto rank = pi[uint64_t(copy) * N + n];
            out.ranks[n][copy] = rank;
            memcpy(out.expanded.data() + uint64_t(rank) * entry, logical.data() + n * entry, entry);
        }
    return out;
}

inline Json pbc_manifest_standard_v3(const Config &c) {
    return {{"layout_version", 3},
            {"pbc_variant", "standard"},
            {"N", c.N},
            {"w", 3},
            {"physical_slots", 3 * c.N},
            {"entry_bytes", c.entry},
            {"layout_seed", c.layout_seed},
            {"epoch", c.epoch}};
}
inline void validate_pbc_manifest_standard_v3(const Config &c) {
    require(read_json(c.common / "pbc_manifest_standard_v3.json") == pbc_manifest_standard_v3(c),
            "Standard PBC v3 manifest mismatch");
}

struct PbcParams {
    uint64_t m_req = 0, m = 0, B = 0;
    uint32_t logB = 0;
    double hall_log2 = std::numeric_limits<double>::quiet_NaN();
    uint64_t D = 0, z = 0, C = 0;
    uint32_t logD = 0;
};
inline long double log_choose(uint64_t n, uint64_t k) {
    if (n < k)
        return -INFINITY;
    return lgammal(n + 1) - lgammal(k + 1) - lgammal(n - k + 1);
}
inline long double log_add(long double a, long double b) {
    if (!std::isfinite(a))
        return b;
    if (!std::isfinite(b))
        return a;
    auto x = std::max(a, b);
    return x + log1pl(expl(std::min(a, b) - x));
}
inline long double strict_hall_bound_log2(uint64_t N, uint64_t t, uint64_t m) {
    require(pow2(N) && t >= 1 && t <= N && m >= 3 && m % 3 == 0 && pow2(m / 3) && 3 * N % m == 0,
            "strict Hall-bound dimensions");
    if (t == 1)
        return -INFINITY;
    const uint64_t total = 3 * N, B = total / m;
    long double sum = -INFINITY;
    for (uint64_t r = 2; r <= t; r++) {
        auto term = log_choose(t, r) + log_choose(m, r - 1) + log_choose((r - 1) * B, 3 * r) -
                    log_choose(total, 3 * r);
        sum = log_add(sum, term);
    }
    return sum / logl(2);
}
inline PbcParams pbc_params(uint64_t N, uint64_t t, double lambda = 40) {
    require(pow2(N) && t > 0 && t <= N, "Standard PBC requires power-of-two N and 0<t<=N");
    const uint64_t total = 3 * N;
    for (uint64_t m = 3; m <= total; m *= 2) {
        if (m >= t) {
            auto bound = strict_hall_bound_log2(N, t, m);
            if (bound <= -lambda) {
                PbcParams p;
                p.m_req = m;
                p.m = m;
                p.B = total / m;
                p.logB = __builtin_ctzll(p.B);
                p.hall_log2 = double(bound);
                require(m * p.B == total && pow2(p.B), "illegal Standard PBC dimensions");
                return p;
            }
        }
        if (m > total / 2)
            break;
    }
    throw std::runtime_error("PBC_PROFILE_UNSUPPORTED_FOR_T");
}

struct Candidate {
    uint32_t bucket, offset;
};
struct PbcSchedule {
    bool success = false;
    uint64_t matching = 0;
    std::vector<int64_t> bucket_target;
    std::vector<uint32_t> bucket_offset;
};
inline PbcSchedule exact_schedule(const std::vector<uint64_t> &ids,
                                  const std::vector<std::array<uint32_t, 3>> &ranks,
                                  const PbcParams &p, bool force_failure = false) {
    std::vector<std::vector<Candidate>> graph(ids.size());
    for (size_t x = 0; x < ids.size(); x++)
        for (auto rank : ranks.at(ids[x])) {
            Candidate c{uint32_t(rank / p.B), uint32_t(rank % p.B)};
            if (std::none_of(graph[x].begin(), graph[x].end(),
                             [&](auto a) { return a.bucket == c.bucket; }))
                graph[x].push_back(c);
        }
    std::vector<int64_t> owner(p.m, -1), choice(ids.size(), -1);
    std::vector<uint32_t> offset(ids.size());
    std::function<bool(size_t, std::vector<uint8_t> &)> augment = [&](size_t x,
                                                                      std::vector<uint8_t> &seen) {
        for (auto c : graph[x])
            if (!seen[c.bucket]) {
                seen[c.bucket] = 1;
                auto old = owner[c.bucket];
                if (old < 0 || augment(old, seen)) {
                    owner[c.bucket] = x;
                    choice[x] = c.bucket;
                    offset[x] = c.offset;
                    return true;
                }
            }
        return false;
    };
    uint64_t matched = 0;
    for (size_t x = 0; x < ids.size(); x++) {
        std::vector<uint8_t> seen(p.m);
        if (augment(x, seen))
            matched++;
    }
    PbcSchedule s;
    s.success = matched == ids.size() && !force_failure;
    s.matching =
        force_failure ? std::min<uint64_t>(matched, ids.size() ? ids.size() - 1 : 0) : matched;
    s.bucket_target.assign(p.m, -1);
    s.bucket_offset.resize(p.m);
    if (s.success)
        for (size_t x = 0; x < ids.size(); x++) {
            s.bucket_target[choice[x]] = x;
            s.bucket_offset[choice[x]] = offset[x];
        }
    return s;
}

inline void dpf_accumulate_into(const dpf_api::Key &key, uint32_t logB, const uint64_t *database,
                                uint32_t entry, uint64_t *out, bool use_evalfull8) {
    auto mask = dpf_api::eval_full(key, logB, use_evalfull8 && logB >= 10);
    auto B = uint64_t(1) << logB;
    for (uint64_t ell = 0; ell < B; ell++) {
        uint64_t select = 0 - uint64_t((mask[ell >> 3] >> (ell & 7)) & 1);
        auto source = database + ell * entry / 8;
        for (uint32_t word = 0; word < entry / 8; word++)
            out[word] ^= source[word] & select;
    }
}

struct DpfClientStats {
    PbcParams params;
    bool success = false, dummy_zero_valid = false;
    uint64_t matching = 0, dummy_buckets = 0;
    double param_ms = 0, schedule_ms = 0, gen_ms = 0, reconstruct_ms = 0, wall_ms = 0;
    uint64_t query_bytes = 0, response_bytes = 0;
};
class DpfPbcClient {
    const Config &c_;
    std::vector<std::array<uint32_t, 3>> ranks_;

  public:
    explicit DpfPbcClient(const Config &c) : c_(c) {
        validate_pbc_manifest_standard_v3(c);
        auto raw = load_binary(c.common / "pbc_ranks_standard_v3.bin", c.common_header(3 * c.N),
                               "SHPRPBS3", 3 * c.N * 4);
        ranks_.resize(c.N);
        memcpy(ranks_.data(), raw.data(), raw.size());
        for (auto r : ranks_)
            for (auto rank : r)
                require(rank < 3 * c.N, "invalid Standard PBC rank");
    }
    std::pair<std::vector<Bytes>, DpfClientStats> retrieve(Link &link,
                                                           const std::vector<uint64_t> &ids,
                                                           const std::string &run,
                                                           bool force_failure = false) {
        DpfClientStats st;
        auto wall = Clock::now(), timer = wall;
        st.params = pbc_params(c_.N, ids.size(), c_.get<double>("payload.pbc.lambda_stat", 40));
        st.param_ms = elapsed(timer);
        timer = Clock::now();
        auto schedule = exact_schedule(ids, ranks_, st.params, force_failure);
        st.success = schedule.success;
        st.matching = schedule.matching;
        st.dummy_buckets = st.params.m - (st.success ? ids.size() : 0);
        st.schedule_ms = elapsed(timer);
        timer = Clock::now();
        std::array<Writer, 2> query;
        for (auto &writer : query) {
            writer.u32(st.params.m);
            writer.u32(st.params.logB);
        }
        size_t key_len = 0;
        for (size_t q = 0; q < st.params.m; q++) {
            uint64_t alpha;
            random_bytes(&alpha, sizeof(alpha));
            alpha &= st.params.B - 1;
            if (schedule.success && schedule.bucket_target[q] >= 0)
                alpha = schedule.bucket_offset[q];
            require(alpha < st.params.B, "DPF alpha outside Standard bucket");
            auto keys = dpf_api::gen(alpha, st.params.logB);
            if (!key_len)
                key_len = keys.first.size();
            require(keys.first.size() == key_len && keys.second.size() == key_len,
                    "DPF key length shape");
            query[0].u32(keys.first.size());
            query[0].raw(keys.first.data(), keys.first.size());
            query[1].u32(keys.second.size());
            query[1].raw(keys.second.data(), keys.second.size());
        }
        st.gen_ms = elapsed(timer);
        st.query_bytes = query[0].b.size() + query[1].b.size();
        auto f0 = std::async(std::launch::async, [&]() {
            link.send(1, query[0].b, "DPF_QUERY/" + run);
            return link.recv(1, "DPF_RESPONSE/" + run);
        });
        link.send(2, query[1].b, "DPF_QUERY/" + run);
        auto b1 = link.recv(2, "DPF_RESPONSE/" + run), b0 = f0.get();
        st.response_bytes = b0.size() + b1.size();
        timer = Clock::now();
        Reader r0(b0), r1(b1);
        require(r0.u32() == st.params.m && r1.u32() == st.params.m, "DPF response m mismatch");
        require(r0.u32() == c_.entry && r1.u32() == c_.entry, "DPF response entry mismatch");
        std::vector<Bytes> out(ids.size(), Bytes(c_.entry));
        for (size_t q = 0; q < st.params.m; q++) {
            auto target = schedule.bucket_target[q];
            for (size_t j = 0; j < c_.entry; j++) {
                auto value = r0.p[r0.pos + j] ^ r1.p[r1.pos + j];
                if (schedule.success && target >= 0)
                    out[target][j] = value;
            }
            r0.pos += c_.entry;
            r1.pos += c_.entry;
        }
        r0.end();
        r1.end();
        st.reconstruct_ms = elapsed(timer);
        st.wall_ms = elapsed(wall);
        if (!st.success)
            out.clear();
        return {std::move(out), st};
    }
};

struct DpfServerStats {
    double eval_ms = 0;
    uint64_t query_bytes = 0, response_bytes = 0;
    uint32_t threads = 1;
};
class DpfPbcServer {
    const Config &c_;
    const Words &db_;
    int threads_;

  public:
    DpfPbcServer(const Config &c, const Words &db, int peer)
        : c_(c), db_(db), threads_(std::max(1, c.threads(peer == 1 ? "s0" : "s1") - 1)) {
        validate_pbc_manifest_standard_v3(c);
        require(db.size() * 8 == 3 * c.N * c.entry, "Standard PBC database size mismatch");
    }
    DpfServerStats respond(Link &link, const std::string &run) {
        DpfServerStats st;
        st.threads = threads_;
        auto query = link.recv(0, "DPF_QUERY/" + run);
        st.query_bytes = query.size();
        Reader reader(query);
        auto m = reader.u32(), logB = reader.u32();
        uint64_t B = uint64_t(1) << logB;
        require(uint64_t(m) * B == 3 * c_.N && m >= 3 && m % 3 == 0 && pow2(m / 3),
                "DPF public Standard profile mismatch");
        std::vector<dpf_api::Key> keys(m);
        size_t key_len = 0;
        for (auto &key : keys) {
            auto n = reader.u32();
            reader.check(n);
            if (!key_len)
                key_len = n;
            require(n == key_len, "DPF batch key length mismatch");
            key.assign(reader.p + reader.pos, reader.p + reader.pos + n);
            reader.pos += n;
        }
        reader.end();
        Words answers(uint64_t(m) * c_.entry / 8);
        auto begin = Clock::now();
#pragma omp parallel for schedule(static) num_threads(threads_)
        for (uint32_t q = 0; q < m; q++)
            dpf_accumulate_into(keys[q], logB, db_.data() + uint64_t(q) * B * c_.entry / 8,
                                c_.entry, answers.data() + uint64_t(q) * c_.entry / 8,
                                c_.get<bool>("payload.dpf.use_evalfull8", true));
        st.eval_ms = elapsed(begin);
        Writer response;
        response.u32(m);
        response.u32(c_.entry);
        response.raw(answers.data(), answers.size() * 8);
        st.response_bytes = response.b.size();
        link.send(0, response.b, "DPF_RESPONSE/" + run);
        return st;
    }
};
}
