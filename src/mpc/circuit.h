#pragma once
#include "common/core.h"
namespace shkr {
struct Gate {
    std::string op;
    int a = -1, b = -1, depth = 0, triple = -1, leaf = -1;
};
struct Circuit {
    std::vector<Gate> gates;
    int output = -1, depth = 0, triples = 0;
    std::vector<int> leaves;
    int add_binary(const std::string &op, int a, int b) {
        int d = std::max(gates[a].depth, gates[b].depth);
        bool nonlinear = op == "AND" || op == "OR";
        if (nonlinear)
            d++;
        gates.push_back({op, a, b, d, nonlinear ? triples++ : -1, -1});
        depth = std::max(depth, d);
        return int(gates.size()) - 1;
    }
    int balanced(const std::string &op, std::vector<int> nodes) {
        require(!nodes.empty(), "empty Boolean gate");
        while (nodes.size() > 1) {
            std::vector<int> next;
            for (size_t i = 0; i < nodes.size(); i += 2)
                next.push_back(i + 1 < nodes.size() ? add_binary(op, nodes[i], nodes[i + 1])
                                                    : nodes[i]);
            nodes = std::move(next);
        }
        return nodes[0];
    }
    int compile(const Json &ast) {
        if (ast.is_number_integer()) {
            int leaf = ast.get<int>();
            require(leaf >= 0, "negative leaf index");
            gates.push_back({"LEAF", -1, -1, 0, -1, int(leaves.size())});
            leaves.push_back(leaf);
            return int(gates.size()) - 1;
        }
        auto op = ast.at("op").get<std::string>();
        if (op == "NOT") {
            int a = compile(ast.at("child"));
            gates.push_back({op, a, -1, gates[a].depth, -1, -1});
            return int(gates.size()) - 1;
        }
        require(op == "AND" || op == "OR" || op == "XOR", "unsupported Boolean operator: " + op);
        std::vector<int> v;
        for (const auto &c : ast.at("children"))
            v.push_back(compile(c));
        return balanced(op, v);
    }
    explicit Circuit(const Json &ast) {
        output = compile(ast);
    }
    Words reference(const std::vector<Words> &inputs, uint64_t n) const {
        std::vector<Words> v(gates.size());
        for (size_t i = 0; i < gates.size(); i++) {
            auto &g = gates[i];
            if (g.op == "LEAF")
                v[i] = inputs.at(g.leaf);
            else {
                v[i] = v[g.a];
                for (size_t w = 0; w < v[i].size(); w++) {
                    if (g.op == "NOT")
                        v[i][w] = ~v[i][w];
                    else if (g.op == "AND")
                        v[i][w] &= v[g.b][w];
                    else if (g.op == "OR")
                        v[i][w] |= v[g.b][w];
                    else
                        v[i][w] ^= v[g.b][w];
                }
                mask_tail(v[i], n);
            }
        }
        return v.at(output);
    }
};
}
