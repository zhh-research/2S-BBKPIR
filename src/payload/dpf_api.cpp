#include "payload/dpf_api.h"
#include <dpf.h>
namespace shks::dpf_api {
std::pair<Key, Key> gen(size_t alpha, size_t logn) {
    return DPF::Gen(alpha, logn);
}
std::vector<uint8_t> eval_full(const Key &key, size_t logn, bool vectorized) {
    return vectorized ? DPF::EvalFull8(key, logn) : DPF::EvalFull(key, logn);
}
}
