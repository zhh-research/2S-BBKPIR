#include "common/config.h"
#include "crypto/symmetric.h"
using namespace shkr;
int main(int argc, char **argv) {
    try {
        std::vector<char *> config_args{argv[0]};
        std::string result, payload, report;
        for (int i = 1; i < argc; i++) {
            std::string a = argv[i];
            if (a == "--result") {
                require(i + 1 < argc, "missing result file");
                result = argv[++i];
            } else if (a == "--payload") {
                require(i + 1 < argc, "missing payload file");
                payload = argv[++i];
            } else if (a == "--report") {
                require(i + 1 < argc, "missing report file");
                report = argv[++i];
            } else
                config_args.push_back(argv[i]);
        }
        Config c(config_args.size(), config_args.data());
        auto w = workload(c);
        Circuit circuit(w.ast);
        std::vector<uint32_t> rows;
        for (auto leaf : circuit.leaves)
            rows.push_back(w.rows[leaf]);
        auto expected = circuit.reference(load_plain_rows(c, rows), c.N);
        auto actual = words(load_binary(result, c.header(1), "SHPRRES1", c.W * 8), c.W);
        require(actual == expected, "final bitmap differs from plaintext Boolean reference");
        auto indices = support(expected, c.N);
        Writer index_wire;
        for (auto index : indices)
            index_wire.u64(index);
        Bytes reference_payload;
        if (c.payload) {
            auto got = load_binary(payload, c.header(indices.size()), "SHPRREC1",
                                   indices.size() * (c.entry - 28));
            std::ifstream input(c.corpus / "payload_plain.bin", std::ios::binary);
            require(bool(input), "reference payload unavailable");
            Bytes plain(c.entry - 28);
            reference_payload.reserve(got.size());
            for (size_t i = 0; i < indices.size(); i++) {
                input.seekg(48 + indices[i] * (c.entry - 28));
                input.read((char *)plain.data(), plain.size());
                require(bool(input), "reference payload truncated");
                Reader r(got.data() + i * plain.size(), plain.size());
                require(r.u64() == indices[i], "retrieved record index mismatch");
                require(std::equal(plain.begin(), plain.end(), got.begin() + i * plain.size()),
                        "retrieved payload byte mismatch");
                reference_payload.insert(reference_payload.end(), plain.begin(), plain.end());
            }
        }
        if (!report.empty())
            write_json(report, {{"actual_t", indices.size()},
                                {"F_hash", sha256_hex(expected)},
                                {"I_hash", sha256_hex(index_wire.b)},
                                {"reference_result_hash", sha256_hex(reference_payload)}});
        return 0;
    } catch (const std::exception &e) {
        std::cerr << "VERIFY ERROR: " << e.what() << std::endl;
        return 1;
    }
}
