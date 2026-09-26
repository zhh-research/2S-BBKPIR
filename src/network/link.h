#pragma once
#include "common/core.h"
#include <atomic>
#include <brpc/protocol.h>
#include <string_view>
#include <yacl/link/factory.h>
namespace shks {
inline constexpr std::array<std::string_view, 15> stage_names = {
    "QUERY_BATCH",  "OT_LONG",   "RESHARE",      "BEAVER_OPEN",     "REVEAL",
    "PAYLOAD_META", "DPF_QUERY", "DPF_RESPONSE", "NAIVE_DPF_QUERY", "NAIVE_DPF_RESPONSE",
    "OPRF_REQ",     "OPRF_RESP", "SETUP",        "CONTROL",         "OTHER"};
struct NetSnapshot {
    uint64_t sent = 0, recv = 0;
    std::array<uint64_t, stage_names.size()> stages{};
    std::array<uint64_t, 3> peers{};
};
inline Json diagnostic_delta(const NetSnapshot &start, const NetSnapshot &end) {
    Json stages = Json::object(), peers = Json::object();
    for (size_t i = 0; i < stage_names.size(); i++)
        if (end.stages[i] != start.stages[i])
            stages[std::string(stage_names[i])] = end.stages[i] - start.stages[i];
    for (size_t i = 0; i < 3; i++)
        if (end.peers[i] != start.peers[i])
            peers[std::to_string(i)] = end.peers[i] - start.peers[i];
    return {{"stage_sent_bytes", stages}, {"peer_sent_bytes", peers}};
}
class Link {
    std::shared_ptr<yacl::link::Context> ctx_;
    int rank_;
    bool trace_;
    std::array<std::string, 3> send_prefix_, recv_prefix_;
    std::atomic<uint64_t> sent_{0}, recv_{0};
    std::array<std::atomic<uint64_t>, stage_names.size()> stages_{};
    std::array<std::atomic<uint64_t>, 3> peers_{};
    void send_view(int peer, const void *data, size_t size, const std::string &tag) {
        if (trace_)
            std::cerr << "rank=" << rank_ << " send " << peer << " " << tag << " n=" << size
                      << std::endl;

        ctx_->SendInternal(peer, send_prefix_.at(peer) + tag, yacl::ByteContainerView(data, size));
        sent_.fetch_add(size, std::memory_order_relaxed);
        const auto name = std::string_view(tag).substr(0, tag.find('/'));
        size_t stage = stage_names.size() - 1;
        for (size_t i = 0; i < stage_names.size() - 1; i++)
            if (stage_names[i] == name) {
                stage = i;
                break;
            }
        stages_[stage].fetch_add(size, std::memory_order_relaxed);
        peers_[peer].fetch_add(size, std::memory_order_relaxed);
    }
    auto receive(int peer, const std::string &tag) {
        if (trace_)
            std::cerr << "rank=" << rank_ << " recv " << peer << " " << tag << std::endl;
        auto b = ctx_->RecvInternal(peer, recv_prefix_.at(peer) + tag);
        recv_.fetch_add(b.size(), std::memory_order_relaxed);
        return b;
    }

  public:
    Link(int rank, const std::vector<std::string> &addresses)
        : rank_(rank), trace_(std::getenv("SHKS_TRACE") != nullptr) {
        yacl::link::ContextDesc d;
        d.id = "SHPR";
        d.recv_timeout_ms = 1800000;
        d.http_timeout_ms = 1800000;

        constexpr uint64_t transport_limit = 128ULL * 1024 * 1024;
        brpc::FLAGS_max_body_size = transport_limit;
        d.http_max_payload_size = transport_limit;
        for (int i = 0; i < 3; i++) {
            d.parties.emplace_back(std::to_string(i), addresses.at(i));
            send_prefix_[i] = "SHPR/" + std::to_string(rank) + "/" + std::to_string(i) + "/";
            recv_prefix_[i] = "SHPR/" + std::to_string(i) + "/" + std::to_string(rank) + "/";
        }
        ctx_ = yacl::link::FactoryBrpc().CreateContext(d, rank);
        ctx_->ConnectToMesh();
    }
    ~Link() {
        if (ctx_ && std::uncaught_exceptions() == 0)
            ctx_->WaitLinkTaskFinish();
    }
    void send(int peer, const Bytes &b, const std::string &tag) {
        send_view(peer, b.data(), b.size(), tag);
    }
    void send(int peer, const Words &b, const std::string &tag) {
        send_view(peer, b.data(), b.size() * 8, tag);
    }
    Bytes recv(int peer, const std::string &tag) {
        auto b = receive(peer, tag);
        auto p = static_cast<const uint8_t *>(b.data());
        return Bytes(p, p + b.size());
    }
    void recv_into(int peer, const std::string &tag, Words &out) {
        auto b = receive(peer, tag);
        require(size_t(b.size()) == out.size() * 8, "bitmap wire size mismatch");
        if (b.size())
            memcpy(out.data(), b.data(), b.size());
    }
    Words recv_words(int peer, const std::string &tag, size_t n) {
        Words out(n);
        recv_into(peer, tag, out);
        return out;
    }
    void control_send(int peer, const std::string &tag) {
        send(peer, Bytes{1}, tag);
    }
    void control_recv(int peer, const std::string &tag) {
        require(recv(peer, tag) == Bytes{1}, "control mismatch");
    }

    NetSnapshot snapshot() const {
        NetSnapshot s;
        s.sent = sent_.load(std::memory_order_relaxed);
        s.recv = recv_.load(std::memory_order_relaxed);
        for (size_t i = 0; i < s.stages.size(); i++)
            s.stages[i] = stages_[i].load(std::memory_order_relaxed);
        for (size_t i = 0; i < 3; i++)
            s.peers[i] = peers_[i].load(std::memory_order_relaxed);
        return s;
    }
};
}
