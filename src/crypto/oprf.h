#pragma once
#include "crypto/symmetric.h"
#include <apsi/item.h>
#include <apsi/oprf/ecpoint.h>
#include <array>
#include <istream>
#include <ostream>
namespace shkr {
using FourQPoint = apsi::oprf::ECPoint;
class OprfKey {
    std::array<unsigned char, FourQPoint::order_size> key_{};

  public:
    static constexpr size_t key_size = FourQPoint::order_size;
    OprfKey() {
        FourQPoint::MakeRandomNonzeroScalar(FourQPoint::scalar_span_type{key_.data(), key_.size()});
    }
    auto span() const {
        return FourQPoint::scalar_span_const_type{key_.data(), key_.size()};
    }
    void save(std::ostream &out) const {
        out.write(reinterpret_cast<const char *>(key_.data()), key_.size());
        require(bool(out), "OPRF key save failed");
    }
    void load(std::istream &in) {
        in.read(reinterpret_cast<char *>(key_.data()), key_.size());
        require(bool(in), "OPRF key load failed");
    }
};
inline apsi::Item oprf_item(uint64_t epoch, uint64_t idx) {
    auto input = payload_input(epoch, idx);
    return apsi::Item(std::string(reinterpret_cast<const char *>(input.data()), input.size()));
}
inline Digest point_digest(FourQPoint &point) {
    Digest out{};
    point.extract_hash(FourQPoint::hash_span_type{out.data(), out.size()});
    return out;
}
inline Digest direct_oprf(const OprfKey &key, uint64_t epoch, uint64_t idx) {
    auto item = oprf_item(epoch, idx);
    FourQPoint point(item.get_as<const unsigned char>());
    require(point.scalar_multiply(key.span(), true), "FourQ direct OPRF multiplication failed");
    return point_digest(point);
}
inline Bytes oprf_evaluate(const OprfKey &key, const Bytes &request) {
    require(request.size() % FourQPoint::save_size == 0, "OPRF request size");
    Bytes response(request.size());
    for (size_t off = 0; off < request.size(); off += FourQPoint::save_size) {
        FourQPoint point;
        point.load(
            FourQPoint::point_save_span_const_type{request.data() + off, FourQPoint::save_size});
        require(point.scalar_multiply(key.span(), true), "FourQ OPRF query point rejected");
        point.save(FourQPoint::point_save_span_type{response.data() + off, FourQPoint::save_size});
    }
    return response;
}
class OprfClient {
    size_t count_;
    Bytes query_;
    std::vector<FourQPoint::scalar_type> inverse_;

  public:
    OprfClient(uint64_t epoch, const std::vector<uint64_t> &indices)
        : count_(indices.size()), query_(count_ * FourQPoint::save_size), inverse_(count_) {
        for (size_t i = 0; i < count_; i++) {
            auto item = oprf_item(epoch, indices[i]);
            FourQPoint point(item.get_as<const unsigned char>());
            FourQPoint::scalar_type blind;
            FourQPoint::MakeRandomNonzeroScalar(
                FourQPoint::scalar_span_type{blind.data(), blind.size()});
            FourQPoint::InvertScalar(
                FourQPoint::scalar_span_const_type{blind.data(), blind.size()},
                FourQPoint::scalar_span_type{inverse_[i].data(), inverse_[i].size()});
            require(point.scalar_multiply(
                        FourQPoint::scalar_span_const_type{blind.data(), blind.size()}, false),
                    "FourQ blind failed");
            point.save(FourQPoint::point_save_span_type{query_.data() + i * FourQPoint::save_size,
                                                        FourQPoint::save_size});
        }
    }
    Bytes query() const {
        return query_;
    }
    std::vector<Digest> finish(const Bytes &response) const {
        require(response.size() == count_ * FourQPoint::save_size, "OPRF response size");
        std::vector<Digest> out(count_);
        for (size_t i = 0; i < count_; i++) {
            FourQPoint point;
            point.load(FourQPoint::point_save_span_const_type{
                response.data() + i * FourQPoint::save_size, FourQPoint::save_size});
            require(point.scalar_multiply(
                        FourQPoint::scalar_span_const_type{inverse_[i].data(), inverse_[i].size()},
                        false),
                    "FourQ unblind failed");
            out[i] = point_digest(point);
        }
        return out;
    }
};
inline void oprf_consistency_test() {
    OprfKey key;
    std::vector<uint64_t> ids(32);
    for (size_t i = 0; i < ids.size(); i++)
        ids[i] = i * 0x102030405ull;
    OprfClient client(7, ids);
    auto out = client.finish(oprf_evaluate(key, client.query()));
    for (size_t i = 0; i < ids.size(); i++)
        require(out[i] == direct_oprf(key, 7, ids[i]), "direct/oblivious FourQ OPRF mismatch");
}
}
