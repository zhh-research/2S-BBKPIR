#pragma once
#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>
namespace shkr::dpf_api {
using Key = std::vector<uint8_t>;
std::pair<Key, Key> gen(size_t alpha, size_t logn);
std::vector<uint8_t> eval_full(const Key &key, size_t logn, bool vectorized);
}
