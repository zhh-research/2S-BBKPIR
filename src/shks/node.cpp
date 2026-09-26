#include "preprocess/artifacts.h"
#include "crypto/kk13.h"
#include "mpc/boolean.h"
#include "payload/dpf_pbc.h"
#include <future>
#include <iomanip>
#include <unistd.h>
#include <spawn.h>
#include <sys/wait.h>
extern char **environ;
namespace shks {
struct EndpointSnapshot {
    double cpu;
    NetSnapshot net;
    uint64_t ot_sent, ot_recv;
};
inline EndpointSnapshot snapshot(Link &link, const std::vector<KK13 *> &ots) {
    uint64_t s = 0, r = 0;
    for (auto *ot : ots) {
        auto x = ot->counters();
        s += x.first;
        r += x.second;
    }
    return {cpu_ms(), link.snapshot(), s, r};
}
inline Json delta(const EndpointSnapshot &start, const EndpointSnapshot &end) {
    return {{"cpu_ms", end.cpu - start.cpu},
            {"yacl_sent", end.net.sent - start.net.sent},
            {"yacl_recv", end.net.recv - start.net.recv},
            {"ot_sent", end.ot_sent - start.ot_sent},
            {"ot_recv", end.ot_recv - start.ot_recv}};
}
inline std::string hostpart(const std::string &s) {
    return s.substr(0, s.rfind(':'));
}
inline void send_json(Link &l, int peer, const Json &j, const std::string &tag) {
    auto s = j.dump();
    l.send(peer, Bytes(s.begin(), s.end()), tag);
}
inline Json recv_json(Link &l, int peer, const std::string &tag) {
    auto b = l.recv(peer, tag);
    return Json::parse(b);
}
struct Tuple {
    uint64_t token;
    uint32_t eta;
    std::vector<uint32_t> q;
};
inline std::vector<Tuple> parse_query(const Bytes &b, const Config &c) {
    Reader r(b);
    require(r.u32() == uint32_t(c.k) && r.u32() == c.p, "query batch header mismatch");
    std::vector<Tuple> qs(c.k);
    for (auto &q : qs) {
        q.token = r.u64();
        q.eta = r.u32();
        require(q.token < c.tokens && q.eta < c.L, "query metadata out of range");
        q.q.resize(c.p);
        for (auto &j : q.q) {
            j = r.u32();
            require(j < c.L, "query slot out of range");
        }
    }
    r.end();
    return qs;
}

int server(const Config &c, int b) {
    auto data = load_server(c, b);
    Link link(b + 1, c.addresses);
    auto ast = recv_json(link, 0, "SETUP/ast");
    Circuit circuit(ast);
    c.validate_pool(circuit);
    KK13 ot(
        true, hostpart(c.addresses[b + 1]),
        c.get<uint16_t>(b == 0 ? "network.ot_s0_port" : "network.ot_s1_port", b == 0 ? 9400 : 9401),
        c.p);
    std::unique_ptr<DpfPbcServer> dpf;
    if (c.payload)
        dpf = std::make_unique<DpfPbcServer>(c, data.pbc_database, b + 1);
    std::vector<KK13 *> ots{&ot};
    BooleanWorkspace boolean(c, circuit);

    std::vector<Words> rho(c.k, Words(c.W)), y(c.k, Words(c.W)), mask(c.k, Words(c.W));
    Words ciphertext(size_t(c.k) * c.p * c.W), shares(size_t(c.k) * c.W);
    for (uint64_t run = 0; run < uint64_t(c.warmup + c.repetitions); run++) {
        auto id = std::to_string(run);
        link.control_send(0, "CONTROL/ready/" + id);
        link.control_recv(0, "CONTROL/arm/" + id);
        link.control_send(0, "CONTROL/armed/" + id);
        auto start = snapshot(link, ots);
        auto qs = parse_query(link.recv(0, "QUERY_BATCH/" + id), c);
        auto t = Clock::now();
#pragma omp parallel for schedule(static) if (size_t(c.k) * c.W >= 4096)
        for (int leaf = 0; leaf < c.k; leaf++) {
            auto &q = qs[leaf];
            random_bytes(rho[leaf].data(), c.W * 8);
            mask_tail(rho[leaf], c.N);
            const auto &token = data.tokens[q.token];
            if (token.host != uint32_t(b))
                prg_into(token.seed, hint_context(c.epoch, q.token, q.eta), c.N, mask[leaf].data());
        }
        const size_t blocks = (c.W + 511) / 512;
#pragma omp parallel for collapse(2) schedule(static) if (size_t(c.k) * c.W >= 4096)
        for (int leaf = 0; leaf < c.k; leaf++)
            for (size_t block = 0; block < blocks; block++) {
                const auto &q = qs[leaf];
                const auto &token = data.tokens[q.token];
                for (size_t w = block * 512; w < std::min(c.W, (block + 1) * 512); w++) {
                    uint64_t acc = 0;
                    for (uint32_t s = 0; s < c.p; s++)
                        acc ^= data.shares[(s * c.L + q.q[s]) * c.W + w];
                    auto hint =
                        token.host == uint32_t(b) ? token.c[q.eta * c.W + w] : mask[leaf][w];
                    y[leaf][w] = hint ^ acc ^ rho[leaf][w];
                }
            }
        double row_ms = elapsed(t);
        t = Clock::now();
        auto seeds = ot.send(c.k);
        double kk_ms = elapsed(t);
        auto pad_start = Clock::now();
#pragma omp parallel for schedule(static) if (size_t(c.k) * c.p * c.W >= 4096)
        for (size_t task = 0; task < size_t(c.k) * c.p; task++) {
            auto leaf = task / c.p, s = task % c.p;
            auto out = ciphertext.data() + task * c.W;
            prg_into(seeds[task], ot_context(run, b, leaf, s), c.N, out);
            auto row = s * c.L + qs[leaf].q[s];
            for (size_t w = 0; w < c.W; w++)
                out[w] ^= data.shares[row * c.W + w] ^ rho[leaf][w];
        }
        double pad_ms = elapsed(pad_start);
        auto send_start = Clock::now();
        link.send(0, ciphertext, "OT_LONG/" + id);
        double long_send_ms = elapsed(send_start), ot_ms = elapsed(t);
        t = Clock::now();
        link.recv_into(0, "RESHARE/" + id, shares);
        double reshare_wait_ms = elapsed(t);
        auto apply_start = Clock::now();
#pragma omp parallel for schedule(static) if (shares.size() >= 4096)
        for (size_t off = 0; off < shares.size(); off++)
            y[off / c.W][off % c.W] ^= shares[off];
        double reshare_apply_ms = elapsed(apply_start), reshare_ms = elapsed(t);
        t = Clock::now();
        const auto &final = boolean.evaluate(b, link, y, data.triples, run);
        double boolean_ms = elapsed(t);
        link.send(0, final, "REVEAL/" + id);
        auto filter_end = snapshot(link, ots);
        auto end = filter_end;
        DpfServerStats dpf_stats;
        if (c.payload) {
            auto info = link.recv(0, "PAYLOAD_META/" + id);
            Reader r(info);
            auto count = r.u64();
            r.end();
            if (count) {
                auto work = [&]() {
                    auto request = link.recv(0, "OPRF_REQ/" + id);
                    auto response = oprf_evaluate(*data.key, request);
                    link.send(0, response, "OPRF_RESP/" + id);
                };
                auto future = std::async(std::launch::async, work);
                dpf_stats = dpf->respond(link, id);
                future.get();
                end = snapshot(link, ots);
            }
        }
        Json times = {{"shks_row_ms", row_ms},
                      {"ot_online_ms", ot_ms},
                      {"kk13_extension_wait_ms", kk_ms},
                      {"ot_pad_ms", pad_ms},
                      {"ot_long_send_ms", long_send_ms},
                      {"reshare_ms", reshare_ms},
                      {"reshare_wait_ms", reshare_wait_ms},
                      {"reshare_apply_ms", reshare_apply_ms},
                      {"boolean_ms", boolean_ms},
                      {"dpf_eval_ms", dpf_stats.eval_ms},
                      {"dpf_threads", dpf_stats.threads}};
        Json report = {{"role", b == 0 ? "s0" : "s1"},
                       {"pid", getpid()},
                       {"filter", delta(start, filter_end)},
                       {"e2e", delta(start, end)},
                       {"stages", times},
                       {"filter_diagnostics", diagnostic_delta(start.net, filter_end.net)},
                       {"diagnostics", diagnostic_delta(start.net, end.net)}};

        link.control_recv(0, "CONTROL/done/" + id);
        send_json(link, 0, report, "CONTROL/report/" + id);
    }
    return 0;
}

inline std::string csv_cell(const Json &value) {
    std::string s = value.is_string() ? value.get<std::string>() : value.dump();
    std::string out = "\"";
    for (char c : s) {
        if (c == '\"')
            out += '\"';
        out += c;
    }
    return out + '\"';
}
inline void append_result(const Config &c, const Json &row, const Json &detail) {
    auto path = fs::path(c.get<std::string>("benchmark.output", "results/raw_runs.csv"));
    fs::create_directories(path.parent_path());
    bool fresh = !fs::exists(path) || fs::file_size(path) == 0;
    std::ofstream f(path, std::ios::app);
    if (fresh) {
        bool first = true;
        for (auto it = row.begin(); it != row.end(); ++it) {
            if (!first)
                f << ',';
            f << it.key();
            first = false;
        }
        f << '\n';
    }
    bool first = true;
    for (auto it = row.begin(); it != row.end(); ++it) {
        if (!first)
            f << ',';
        f << csv_cell(it.value());
        first = false;
    }
    f << '\n';
    std::ofstream d(path.string() + ".jsonl", std::ios::app);
    d << detail.dump() << '\n';
}

int client(const Config &c) {
    auto w = workload(c);
    Circuit circuit(w.ast);
    auto tokens = load_tokens(c, 0);
    Link link(0, c.addresses);
    for (int peer = 1; peer <= 2; peer++)
        send_json(link, peer, w.ast, "SETUP/ast");
    KK13 ot0(false, hostpart(c.addresses[1]), c.get<uint16_t>("network.ot_s0_port", 9400), c.p);
    KK13 ot1(false, hostpart(c.addresses[2]), c.get<uint16_t>("network.ot_s1_port", 9401), c.p);
    std::vector<KK13 *> ots{&ot0, &ot1};
    std::unique_ptr<DpfPbcClient> dpf;
    if (c.payload) {
        oprf_consistency_test();
        dpf = std::make_unique<DpfPbcClient>(c);
    }
    auto experiment = c.get<std::string>(
        "benchmark.experiment_id",
        c.dataset_id + "_" +
            std::to_string(std::chrono::system_clock::now().time_since_epoch().count()));
    require(experiment.find('/') == std::string::npos && experiment.find("..") == std::string::npos,
            "experiment_id must be a filename component");
    auto verify_root =
        fs::path(c.get<std::string>("benchmark.output", "results/raw_runs.csv")).parent_path() /
        "verification" / experiment;
    fs::create_directories(verify_root);
    auto verify_config = verify_root / "config.json";
    write_json(verify_config, c.j);
    std::array<Words, 2> ciphertext{Words(size_t(c.k) * c.p * c.W), Words(size_t(c.k) * c.p * c.W)},
        selected{Words(size_t(c.k) * c.W), Words(size_t(c.k) * c.W)};
    Words mu(size_t(c.k) * c.W), mu1(mu.size()), a(c.W), b(c.W);
    for (uint64_t run = 0; run < uint64_t(c.warmup + c.repetitions); run++) {
        auto id = std::to_string(run);
        for (int p = 1; p <= 2; p++)
            link.control_recv(p, "CONTROL/ready/" + id);
        for (int p = 1; p <= 2; p++)
            link.control_send(p, "CONTROL/arm/" + id);
        for (int p = 1; p <= 2; p++)
            link.control_recv(p, "CONTROL/armed/" + id);
        auto start = snapshot(link, ots);
        auto wall = Clock::now();
        auto t = wall;
        Writer query;
        query.u32(c.k);
        query.u32(c.p);
        std::vector<uint32_t> choices(c.k);
        for (int leaf = 0; leaf < c.k; leaf++) {
            uint64_t nu = (run * c.k + leaf) % c.tokens;
            auto &token = tokens[nu];
            uint32_t r = w.rows[circuit.leaves[leaf]], s = r / c.L, j = r % c.L;
            choices[leaf] = s;
            uint32_t eta = j ^ token.delta[s], fresh;
            random_bytes(&fresh, 4);
            fresh &= c.L - 1;
            query.u64(nu);
            query.u32(eta);
            for (uint32_t partition = 0; partition < c.p; partition++)
                query.u32(partition == s ? fresh : eta ^ token.delta[partition]);
        }
        double query_build_ms = elapsed(t);
        auto send_start = Clock::now();
        link.send(1, query.b, "QUERY_BATCH/" + id);
        link.send(2, query.b, "QUERY_BATCH/" + id);
        double query_send_ms = elapsed(send_start), querygen_ms = elapsed(t);
        t = Clock::now();
        std::array<double, 2> kk_ms{}, long_recv_ms{}, pad_ms{};
        auto receive = [&](int server, KK13 &ot) {
            auto begin = Clock::now();
            auto seeds = ot.receive(choices);
            kk_ms[server] = elapsed(begin);
            begin = Clock::now();
            link.recv_into(server + 1, "OT_LONG/" + id, ciphertext[server]);
            long_recv_ms[server] = elapsed(begin);
            begin = Clock::now();
#pragma omp parallel for schedule(static)                                                          \
    num_threads(std::max(1, c.threads("client") / 2)) if (size_t(c.k) * c.W >= 4096)
            for (int leaf = 0; leaf < c.k; leaf++) {
                auto out = selected[server].data() + leaf * c.W;
                prg_into(seeds[leaf], ot_context(run, server, leaf, choices[leaf]), c.N, out);
                for (size_t w = 0; w < c.W; w++)
                    out[w] ^= ciphertext[server][(leaf * c.p + choices[leaf]) * c.W + w];
            }
            pad_ms[server] = elapsed(begin);
        };
        auto f0 = std::async(std::launch::async, [&]() { receive(0, ot0); });
        receive(1, ot1);
        f0.get();
        double ot_ms = elapsed(t);
        auto reshare_start = Clock::now();
#pragma omp parallel for schedule(static) if (size_t(c.k) * c.W >= 4096)
        for (int leaf = 0; leaf < c.k; leaf++) {
            random_bytes(mu.data() + leaf * c.W, c.W * 8);
            mu[(leaf + 1) * c.W - 1] &= tail_mask(c.N);
        }
#pragma omp parallel for schedule(static) if (mu.size() >= 4096)
        for (size_t off = 0; off < mu.size(); off++)
            mu1[off] = mu[off] ^ selected[0][off] ^ selected[1][off];
        link.send(1, mu, "RESHARE/" + id);
        link.send(2, mu1, "RESHARE/" + id);
        double reshare_ms = elapsed(reshare_start);
        t = Clock::now();
        link.recv_into(1, "REVEAL/" + id, a);
        link.recv_into(2, "REVEAL/" + id, b);
        double reveal_wait_ms = elapsed(t);
        auto reconstruct_start = Clock::now();
#pragma omp parallel for schedule(static) if (c.W >= 4096)
        for (size_t i = 0; i < c.W; i++)
            a[i] ^= b[i];
        mask_tail(a, c.N);
        double reconstruct_ms = elapsed(reconstruct_start), filter_wall = elapsed(wall);
        auto filter_end = snapshot(link, ots);
        double reveal_ms = elapsed(t);
        auto payload_start = Clock::now(), support_start = payload_start;
        auto ids = support(a, c.N);
        double support_ms = elapsed(support_start), e2e_wall = elapsed(wall);
        auto end = filter_end;
        std::vector<Bytes> plaintext;
        double oprf_ms = 0, kdf_ms = 0;
        DpfClientStats dpf_stats;
        bool payload_valid = true;
        if (c.payload && !ids.empty()) {
            Writer meta;
            meta.u64(ids.size());
            for (int peer = 1; peer <= 2; peer++)
                link.send(peer, meta.b, "PAYLOAD_META/" + id);
            auto fdpf = std::async(std::launch::async, [&]() {
                return dpf->retrieve(link, ids, id,
                                     c.get<bool>("benchmark.force_pbc_failure", false));
            });
            auto oprfstart = Clock::now();
            auto eval = [&](int peer) {
                OprfClient receiver(c.epoch, ids);
                link.send(peer, receiver.query(), "OPRF_REQ/" + id);
                return receiver.finish(link.recv(peer, "OPRF_RESP/" + id));
            };
            auto foprf = std::async(std::launch::async, [&]() { return eval(1); });
            auto z1 = eval(2);
            auto z0 = foprf.get();
            oprf_ms = elapsed(oprfstart);
            auto dpf_result = fdpf.get();
            auto encrypted = std::move(dpf_result.first);
            dpf_stats = dpf_result.second;
            payload_valid = dpf_stats.success;
            t = Clock::now();
            if (payload_valid)
                plaintext.resize(ids.size());
#pragma omp parallel for schedule(static)
            for (size_t i = 0; i < plaintext.size(); i++)
                plaintext[i] = decrypt_payload(payload_key(z0[i], z1[i], c.epoch, ids[i]),
                                               encrypted[i], c.epoch, ids[i]);
            kdf_ms = elapsed(t);
            e2e_wall = elapsed(wall);
            end = snapshot(link, ots);
        } else if (c.payload) {
            e2e_wall = elapsed(wall);
            end = snapshot(link, ots);
            Writer meta;
            meta.u64(0);
            for (int peer = 1; peer <= 2; peer++)
                link.send(peer, meta.b, "PAYLOAD_META/" + id);
        } else {
            e2e_wall = filter_wall;
            end = filter_end;
        }
        double payload_wall = c.payload ? elapsed(payload_start) : 0;
        auto client_diag = diagnostic_delta(start.net, end.net);
        Json row = {
            {"querygen_ms", querygen_ms}, {"ot_online_ms", ot_ms}, {"reveal_ms", reveal_ms}};
        Json client_stages = {{"query_build_ms", query_build_ms},
                              {"query_send_ms", query_send_ms},
                              {"kk13_extension_wait_ms", kk_ms},
                              {"ot_long_receive_ms", long_recv_ms},
                              {"ot_pad_ms", pad_ms},
                              {"reshare_generate_send_ms", reshare_ms},
                              {"final_receive_wait_ms", reveal_wait_ms},
                              {"final_reconstruct_ms", reconstruct_ms}};

        auto result_file = verify_root / (id + "_bitmap.bin"),
             payload_file = verify_root / (id + "_payload.bin");
        save_binary(result_file, c.header(1), "SHPRRES1", a.data(), c.W * 8);
        if (c.payload) {
            Writer records;
            for (const auto &record : plaintext)
                records.raw(record.data(), record.size());
            save_binary(payload_file, c.header(ids.size()), "SHPRREC1", records.b.data(),
                        records.b.size());
        }
        auto verification_report = verify_root / (id + "_verification.json");
        std::vector<std::string> command{
            "./build/shks_verify",       "--config",  verify_config.string(), "--result",
            result_file.string(),        "--payload", payload_file.string(),  "--report",
            verification_report.string()};
        std::vector<char *> argv;
        for (auto &arg : command)
            argv.push_back(arg.data());
        argv.push_back(nullptr);
        pid_t verifier;
        require(posix_spawn(&verifier, argv[0], nullptr, nullptr, argv.data(), environ) == 0,
                "could not start offline verifier");
        int status = 0;
        require(waitpid(verifier, &status, 0) == verifier, "offline verifier wait failed");
        bool correct = WIFEXITED(status) && WEXITSTATUS(status) == 0;
        Json reference = correct ? read_json(verification_report) : Json::object();
        Writer id_wire;
        for (auto index : ids)
            id_wire.u64(index);
        Writer result_wire;
        for (const auto &record : plaintext)
            result_wire.raw(record.data(), record.size());
        auto F_hash = sha256_hex(a), I_hash = sha256_hex(id_wire.b),
             result_hash = sha256_hex(result_wire.b);
        if (correct)
            correct = reference.at("F_hash") == F_hash && reference.at("I_hash") == I_hash &&
                      reference.at("reference_result_hash") == result_hash;
        for (int peer = 1; peer <= 2; peer++)
            link.control_send(peer, "CONTROL/done/" + id);
        auto s0 = recv_json(link, 1, "CONTROL/report/" + id),
             s1 = recv_json(link, 2, "CONTROL/report/" + id);
        auto cf = delta(start, filter_end), ce = delta(start, end);
        auto sf0 = s0["filter"], sf1 = s1["filter"], se0 = s0["e2e"], se1 = s1["e2e"];
        auto sum = [&](const Json &x, const Json &y, const Json &z, const char *key) {
            return x.at(key).get<uint64_t>() + y.at(key).get<uint64_t>() +
                   z.at(key).get<uint64_t>();
        };
        uint64_t mainfilter = sum(cf, sf0, sf1, "yacl_sent"), kk = sum(cf, sf0, sf1, "ot_sent"),
                 maine2e = sum(ce, se0, se1, "yacl_sent");
        auto stage_bytes = [&](const Json &role, const char *stage) {
            return role["diagnostics"]["stage_sent_bytes"].value(stage, uint64_t(0));
        };
        uint64_t dpf_query_bytes = stage_bytes(Json{{"diagnostics", client_diag}}, "DPF_QUERY"),
                 dpf_response_bytes =
                     stage_bytes(s0, "DPF_RESPONSE") + stage_bytes(s1, "DPF_RESPONSE"),
                 oprf_bytes = stage_bytes(Json{{"diagnostics", client_diag}}, "OPRF_REQ") +
                              stage_bytes(s0, "OPRF_RESP") + stage_bytes(s1, "OPRF_RESP");
        correct = correct && payload_valid;
        struct DeprecatedZeroGeometry {
            uint64_t U = 0, m_max = 0, N_pbc = 0, N_pad = 0, D_min = 0, T_data = 0;
        } pbc_geo;
        Json hall_bound =
            std::isnan(dpf_stats.params.hall_log2)
                ? Json(nullptr)
                : (std::isinf(dpf_stats.params.hall_log2) ? Json("-inf")
                                                          : Json(dpf_stats.params.hall_log2));
        uint64_t token_bytes = 0;
        for (const auto &name : {"client_tokens.bin", "s0_tokens.bin", "s1_tokens.bin"})
            token_bytes += fs::file_size(c.artifacts / name) - 48;
        bool benchmark_valid = correct && (c.requested_t == 0 || ids.size() == c.requested_t);
        row.update(
            {{"experiment_id", experiment},
             {"run_index", run},
             {"is_warmup", run < uint64_t(c.warmup)},
             {"benchmark_valid", benchmark_valid},
             {"correct", correct},
             {"dataset_id", c.dataset_id},
             {"N", c.N},
             {"M_real", c.Mr},
             {"M", c.M},
             {"A", c.A},
             {"D", c.D},
             {"p", c.p},
             {"L", c.L},
             {"k", c.k},
             {"query_id", c.query_id},
             {"formula", w.ast.dump()},
             {"requested_t", c.requested_t},
             {"actual_t", ids.size()},
             {"matched_count", ids.size()},
             {"F_hash", F_hash},
             {"I_hash", I_hash},
             {"result_hash", result_hash},
             {"reference_result_hash", reference.value("reference_result_hash", std::string())},
             {"aead_auth_success", c.payload && payload_valid},
             {"final_reveal_mode", "direct"},
             {"entry_bytes", c.entry},
             {"threads_client", c.threads("client")},
             {"threads_s0", c.threads("s0")},
             {"threads_s1", c.threads("s1")},
             {"dpf_threads_s0", s0["stages"]["dpf_threads"]},
             {"dpf_threads_s1", s1["stages"]["dpf_threads"]},
             {"oprf_threads_s0", 1},
             {"oprf_threads_s1", 1},
             {"reuse_tokens", c.reuse_tokens},
             {"reuse_triples", c.reuse_triples},
             {"benchmark_token_reuse_only", c.benchmark_reuse_mode},
             {"filter_online_wall_ms", filter_wall},
             {"client_filter_cpu_ms", cf["cpu_ms"]},
             {"s0_filter_cpu_ms", sf0["cpu_ms"]},
             {"s1_filter_cpu_ms", sf1["cpu_ms"]},
             {"filter_total_cpu_ms", cf["cpu_ms"].get<double>() + sf0["cpu_ms"].get<double>() +
                                         sf1["cpu_ms"].get<double>()},
             {"shks_row_ms_max", std::max(s0["stages"]["shks_row_ms"].get<double>(),
                                          s1["stages"]["shks_row_ms"].get<double>())},
             {"reshare_ms", std::max(s0["stages"]["reshare_ms"].get<double>(),
                                     s1["stages"]["reshare_ms"].get<double>())},
             {"boolean_ms", std::max(s0["stages"]["boolean_ms"].get<double>(),
                                     s1["stages"]["boolean_ms"].get<double>())},
             {"main_yacl_filter_bytes", mainfilter},
             {"kk13_filter_online_bytes", kk},
             {"filter_online_bytes", mainfilter + kk},
             {"support_extract_ms", support_ms},
             {"pbc_w", 3},
             {"pbc_lambda_stat", c.get<double>("payload.pbc.lambda_stat", 40)},
             {"pbc_slack_bits", c.pbc_slack_bits},
             {"pbc_profile_base", c.pbc_profile_base},
             {"pbc_m_req", dpf_stats.params.m_req},
             {"pbc_m", dpf_stats.params.m},
             {"pbc_virtual_slots_U", pbc_geo.U},
             {"pbc_m_max", pbc_geo.m_max},
             {"pbc_N_pbc", pbc_geo.N_pbc},
             {"pbc_N_pad", pbc_geo.N_pad},
             {"pbc_D", dpf_stats.params.D},
             {"pbc_logD", dpf_stats.params.logD},
             {"pbc_D_min", pbc_geo.D_min},
             {"pbc_zero_slots_per_bucket", dpf_stats.params.z},
             {"pbc_data_capacity_C", dpf_stats.params.C},
             {"pbc_total_data_slots_T", pbc_geo.T_data},
             {"dpf_total_domain_positions", ids.empty() ? 0 : pbc_geo.U},
             {"pbc_dummy_buckets", dpf_stats.dummy_buckets},
             {"pbc_dummy_zero_valid", dpf_stats.dummy_zero_valid},
             {"pbc_hall_bound_log2", hall_bound},
             {"pbc_small_t_bound_log2", hall_bound},
             {"cuckoo_success", !c.payload || ids.empty() || dpf_stats.success},
             {"cuckoo_matching_size", dpf_stats.matching},
             {"payload_result_valid", payload_valid},
             {"cuckoo_schedule_ms", dpf_stats.schedule_ms},
             {"pbc_param_ms", dpf_stats.param_ms},
             {"dpf_gen_ms", dpf_stats.gen_ms},
             {"dpf_pir_wall_ms", dpf_stats.wall_ms},
             {"s0_dpf_eval_ms", s0["stages"]["dpf_eval_ms"]},
             {"s1_dpf_eval_ms", s1["stages"]["dpf_eval_ms"]},
             {"dpf_eval_ms_max", std::max(s0["stages"]["dpf_eval_ms"].get<double>(),
                                          s1["stages"]["dpf_eval_ms"].get<double>())},
             {"dpf_reconstruct_ms", dpf_stats.reconstruct_ms},
             {"dpf_query_bytes", dpf_query_bytes},
             {"dpf_response_bytes", dpf_response_bytes},
             {"dpfpir_online_bytes", dpf_query_bytes + dpf_response_bytes},
             {"dual_oprf_ms", oprf_ms},
             {"dual_oprf_online_bytes", oprf_bytes},
             {"kdf_aead_ms", kdf_ms},
             {"payload_online_wall_ms", payload_wall},
             {"e2e_online_wall_ms", e2e_wall},
             {"total_online_time_ms", e2e_wall},
             {"client_e2e_cpu_ms", ce["cpu_ms"]},
             {"s0_e2e_cpu_ms", se0["cpu_ms"]},
             {"s1_e2e_cpu_ms", se1["cpu_ms"]},
             {"e2e_total_cpu_ms", ce["cpu_ms"].get<double>() + se0["cpu_ms"].get<double>() +
                                      se1["cpu_ms"].get<double>()},
             {"client_sent_bytes", ce["yacl_sent"].get<uint64_t>() + ce["ot_sent"].get<uint64_t>()},
             {"s0_sent_bytes", se0["yacl_sent"].get<uint64_t>() + se0["ot_sent"].get<uint64_t>()},
             {"s1_sent_bytes", se1["yacl_sent"].get<uint64_t>() + se1["ot_sent"].get<uint64_t>()},
             {"main_yacl_e2e_bytes", maine2e},
             {"e2e_online_bytes", maine2e + kk},
             {"total_online_comm_bytes", maine2e + kk}});
        row.update(
            {{"benchmark_mode",
              c.get<std::string>("benchmark.mode", c.paper_mode ? "paper_fresh" : "standard")},
             {"categories_per_attribute", c.D},
             {"num_attributes", c.A},
             {"leaf_match_count", c.get<uint64_t>("benchmark.leaf_match_count", 0)},
             {"pbc_variant", "standard"},
             {"pbc_B", dpf_stats.params.B},
             {"pbc_logB", dpf_stats.params.logB},
             {"pbc_physical_slots", c.payload ? 3 * c.N : 0},
             {"pbc_slack_bits", Json(nullptr)},
             {"pbc_profile_base", Json(nullptr)},
             {"pbc_virtual_slots_U", Json(nullptr)},
             {"pbc_m_max", Json(nullptr)},
             {"pbc_N_pbc", Json(nullptr)},
             {"pbc_N_pad", Json(nullptr)},
             {"pbc_D", Json(nullptr)},
             {"pbc_logD", Json(nullptr)},
             {"pbc_D_min", Json(nullptr)},
             {"pbc_zero_slots_per_bucket", Json(nullptr)},
             {"pbc_data_capacity_C", Json(nullptr)},
             {"pbc_C", Json(nullptr)},
             {"pbc_total_data_slots_T", Json(nullptr)},
             {"pbc_dummy_zero_valid", Json(nullptr)},
             {"dpf_total_domain_positions", ids.empty() ? 0 : 3 * c.N},
             {"bitmap_real_storage_bytes", uint64_t(c.Mr) * c.W * 8},
             {"bitmap_padded_storage_bytes", uint64_t(c.M) * c.W * 8},
             {"shks_hint_token_bytes_per_token", token_bytes / c.tokens},
             {"total_preprocessed_token_pool_bytes", token_bytes},
             {"pbc_virtual_db_bytes", 3 * c.N * c.entry},
             {"pbc_rank_mapping_bytes", 3 * c.N * sizeof(uint32_t)},
             {"actual_theta_storage_bytes", 0}});
        Json detail = {{"metrics_version", 5},
                       {"row", row},
                       {"client",
                        {{"pid", getpid()},
                         {"filter", cf},
                         {"e2e", ce},
                         {"stages", client_stages},
                         {"filter_diagnostics", diagnostic_delta(start.net, filter_end.net)},
                         {"diagnostics", client_diag}}},
                       {"s0", s0},
                       {"s1", s1}};
        append_result(c, row, detail);
        std::cout << "run=" << run << " correct=" << correct << " t=" << ids.size()
                  << " filter_ms=" << filter_wall << " e2e_ms=" << e2e_wall
                  << " bytes=" << mainfilter + kk << std::endl;
        if (payload_valid)
            require(correct, "protocol/reference mismatch; results are invalid");
    }
    return 0;
}
}
int main(int argc, char **argv) {
    try {
        shks::Config c(argc, argv);
        shks::require(c.role == "client" || c.role == "s0" || c.role == "s1",
                      "--role client|s0|s1 is required");
        omp_set_dynamic(0);
        omp_set_nested(0);
        omp_set_num_threads(c.threads(c.role));
        if (c.role == "client")
            return shks::client(c);
        return shks::server(c, c.role == "s0" ? 0 : 1);
    } catch (const std::exception &e) {
        std::cerr << "ERROR: " << e.what() << std::endl;
        return 1;
    }
}
