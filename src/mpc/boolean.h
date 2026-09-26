#pragma once
#include "common/config.h"
#include "network/link.h"
#include <omp.h>
namespace shks {

class BooleanWorkspace {
    const Config &c_;
    const Circuit &circuit_;
    std::vector<Words> values_;
    std::vector<const Words *> input_;
    std::vector<std::vector<size_t>> nonlinear_;
    std::vector<Words> opened_, peer_;

  public:
    BooleanWorkspace(const Config &c, const Circuit &circuit)
        : c_(c), circuit_(circuit), values_(circuit.gates.size()), input_(circuit.gates.size()),
          nonlinear_(circuit.depth + 1), opened_(circuit.depth + 1), peer_(circuit.depth + 1) {
        for (size_t i = 0; i < circuit.gates.size(); i++) {
            const auto &g = circuit.gates[i];
            if (g.op != "LEAF")
                values_[i].resize(c.W);
            if (g.triple >= 0)
                nonlinear_[g.depth].push_back(i);
        }
        for (int d = 1; d <= circuit.depth; d++) {
            opened_[d].resize(nonlinear_[d].size() * 2 * c.W);
            peer_[d].resize(opened_[d].size());
        }
    }
    const Words &evaluate(int b, Link &link, const std::vector<Words> &leaves, const Words &triples,
                          uint64_t run) {
        const auto &c = c_;
        const auto &circuit = circuit_;
        auto base = run * circuit.triples;
        for (size_t i = 0; i < circuit.gates.size(); i++) {
            const auto &g = circuit.gates[i];
            input_[i] = g.op == "LEAF" ? &leaves.at(g.leaf) : &values_[i];
        }
        auto local = [&](int depth) {
            for (size_t i = 0; i < circuit.gates.size(); i++) {
                const auto &g = circuit.gates[i];
                if (g.depth != depth || g.triple >= 0 || g.op == "LEAF")
                    continue;
                auto &out = values_[i];
                const auto &a = *input_[g.a];
#pragma omp parallel for schedule(static) if (c.W >= 4096)
                for (size_t w = 0; w < c.W; w++)
                    out[w] = g.op == "NOT" ? (a[w] ^ (b == 0 ? ~uint64_t(0) : 0))
                                           : (a[w] ^ (*input_[g.b])[w]);
                mask_tail(out, c.N);
            }
        };
        local(0);
        for (int depth = 1; depth <= circuit.depth; depth++) {
            const auto &gates = nonlinear_[depth];
            auto &opened = opened_[depth];
            auto &peer = peer_[depth];
            const size_t blocks = (c.W + 511) / 512;
#pragma omp parallel for collapse(2) schedule(static) if (gates.size() * c.W >= 4096)
            for (size_t q = 0; q < gates.size(); q++)
                for (size_t block = 0; block < blocks; block++) {
                    const auto &g = circuit.gates[gates[q]];
                    size_t t = (base + g.triple) % c.triples;
                    const auto &a = *input_[g.a];
                    const auto &bb = *input_[g.b];
                    for (size_t w = block * 512; w < std::min(c.W, (block + 1) * 512); w++) {
                        opened[2 * q * c.W + w] = a[w] ^ triples[3 * t * c.W + w];
                        opened[(2 * q + 1) * c.W + w] = bb[w] ^ triples[(3 * t + 1) * c.W + w];
                    }
                }
            auto tag = "BEAVER_OPEN/" + std::to_string(run) + "/" + std::to_string(depth);
            link.send(2 - b, opened, tag);
            link.recv_into(2 - b, tag, peer);
#pragma omp parallel for collapse(2) schedule(static) if (gates.size() * c.W >= 4096)
            for (size_t q = 0; q < gates.size(); q++)
                for (size_t block = 0; block < blocks; block++) {
                    auto idx = gates[q];
                    const auto &g = circuit.gates[idx];
                    size_t t = (base + g.triple) % c.triples;
                    for (size_t w = block * 512; w < std::min(c.W, (block + 1) * 512); w++) {
                        auto d = opened[2 * q * c.W + w] ^ peer[2 * q * c.W + w],
                             e = opened[(2 * q + 1) * c.W + w] ^ peer[(2 * q + 1) * c.W + w];
                        auto z = triples[(3 * t + 2) * c.W + w] ^
                                 (d & triples[(3 * t + 1) * c.W + w]) ^
                                 (e & triples[3 * t * c.W + w]);
                        if (b == 0)
                            z ^= d & e;
                        if (g.op == "OR")
                            z ^= (*input_[g.a])[w] ^ (*input_[g.b])[w];
                        values_[idx][w] = z;
                    }
                }
            for (auto idx : gates)
                mask_tail(values_[idx], c.N);
            local(depth);
        }
        return *input_[circuit.output];
    }
};
}
