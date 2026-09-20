#include <cstddef>
#include <cstdint>
#include <cstring>
namespace {
constexpr uint64_t iv[8] = {0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL,
                            0xa54ff53a5f1d36f1ULL, 0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
                            0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL};
constexpr uint8_t sigma[12][16] = {{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
                                   {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
                                   {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
                                   {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
                                   {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
                                   {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
                                   {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
                                   {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
                                   {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
                                   {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
                                   {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
                                   {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3}};
inline uint64_t load64(const uint8_t *p) {
    uint64_t x = 0;
    for (unsigned i = 0; i < 8; i++)
        x |= uint64_t(p[i]) << (8 * i);
    return x;
}
inline void store64(uint8_t *p, uint64_t x) {
    for (unsigned i = 0; i < 8; i++)
        p[i] = uint8_t(x >> (8 * i));
}
inline uint64_t rotr(uint64_t x, unsigned n) {
    return (x >> n) | (x << (64 - n));
}
struct State {
    uint64_t h[8], t0 = 0, t1 = 0;
};
inline void store32(uint8_t *p, uint32_t x) {
    for (unsigned i = 0; i < 4; i++)
        p[i] = uint8_t(x >> (8 * i));
}
inline void add_count(State &s, uint64_t n) {
    auto old = s.t0;
    s.t0 += n;
    s.t1 += s.t0 < old;
}
inline void mix(uint64_t &a, uint64_t &b, uint64_t &c, uint64_t &d, uint64_t x, uint64_t y) {
    a = a + b + x;
    d = rotr(d ^ a, 32);
    c += d;
    b = rotr(b ^ c, 24);
    a = a + b + y;
    d = rotr(d ^ a, 16);
    c += d;
    b = rotr(b ^ c, 63);
}
void compress(State &s, const uint8_t block[128], bool last) {
    uint64_t m[16], v[16];
    for (unsigned i = 0; i < 16; i++)
        m[i] = load64(block + 8 * i);
    for (unsigned i = 0; i < 8; i++) {
        v[i] = s.h[i];
        v[i + 8] = iv[i];
    }
    v[12] ^= s.t0;
    v[13] ^= s.t1;
    if (last)
        v[14] = ~v[14];
    for (unsigned r = 0; r < 12; r++) {
        auto q = sigma[r];
        mix(v[0], v[4], v[8], v[12], m[q[0]], m[q[1]]);
        mix(v[1], v[5], v[9], v[13], m[q[2]], m[q[3]]);
        mix(v[2], v[6], v[10], v[14], m[q[4]], m[q[5]]);
        mix(v[3], v[7], v[11], v[15], m[q[6]], m[q[7]]);
        mix(v[0], v[5], v[10], v[15], m[q[8]], m[q[9]]);
        mix(v[1], v[6], v[11], v[12], m[q[10]], m[q[11]]);
        mix(v[2], v[7], v[8], v[13], m[q[12]], m[q[13]]);
        mix(v[3], v[4], v[9], v[14], m[q[14]], m[q[15]]);
    }
    for (unsigned i = 0; i < 8; i++)
        s.h[i] ^= v[i] ^ v[i + 8];
}
int hash_param(void *out, size_t outlen, const void *input, size_t inlen, const void *key,
               size_t keylen, const uint8_t param[64]) {
    State s{};
    for (unsigned i = 0; i < 8; i++)
        s.h[i] = iv[i] ^ load64(param + 8 * i);
    uint8_t block[128]{};
    auto in = static_cast<const uint8_t *>(input);
    if (keylen) {
        std::memcpy(block, key, keylen);
        add_count(s, 128);
        if (inlen)
            compress(s, block, false);
        else {
            compress(s, block, true);
            uint8_t full[64];
            for (unsigned i = 0; i < 8; i++)
                store64(full + 8 * i, s.h[i]);
            std::memcpy(out, full, outlen);
            return 0;
        }
    }
    while (inlen > 128) {
        add_count(s, 128);
        compress(s, in, false);
        in += 128;
        inlen -= 128;
    }
    std::memset(block, 0, sizeof(block));
    if (inlen)
        std::memcpy(block, in, inlen);
    add_count(s, inlen);
    compress(s, block, true);
    uint8_t full[64];
    for (unsigned i = 0; i < 8; i++)
        store64(full + 8 * i, s.h[i]);
    std::memcpy(out, full, outlen);
    return 0;
}
}
extern "C" int blake2b(void *out, size_t outlen, const void *input, size_t inlen, const void *key,
                       size_t keylen) {
    if (!out || outlen == 0 || outlen > 64 || keylen > 64 || (!input && inlen) || (!key && keylen))
        return -1;
    uint8_t p[64]{};
    p[0] = uint8_t(outlen);
    p[1] = uint8_t(keylen);
    p[2] = 1;
    p[3] = 1;
    return hash_param(out, outlen, input, inlen, key, keylen, p);
}
extern "C" int blake2xb(void *out, size_t outlen, const void *input, size_t inlen, const void *key,
                        size_t keylen) {
    if (!out || outlen == 0 || outlen > 0xffffffffULL || keylen > 64 || (!input && inlen) ||
        (!key && keylen))
        return -1;
    uint8_t root_param[64]{};
    root_param[0] = 64;
    root_param[1] = uint8_t(keylen);
    root_param[2] = 1;
    root_param[3] = 1;
    store32(root_param + 12, uint32_t(outlen));
    uint8_t root[64];
    if (hash_param(root, 64, input, inlen, key, keylen, root_param))
        return -1;
    auto dst = static_cast<uint8_t *>(out);
    for (uint32_t i = 0; outlen; i++) {
        auto n = outlen < 64 ? outlen : size_t(64);
        uint8_t leaf_param[64];
        std::memcpy(leaf_param, root_param, 64);
        leaf_param[0] = uint8_t(n);
        leaf_param[1] = 0;
        leaf_param[2] = 0;
        leaf_param[3] = 0;
        store32(leaf_param + 4, 64);
        store32(leaf_param + 8, i);
        leaf_param[16] = 0;
        leaf_param[17] = 64;
        if (hash_param(dst, n, root, 64, nullptr, 0, leaf_param))
            return -1;
        dst += n;
        outlen -= n;
    }
    std::memset(root, 0, sizeof(root));
    return 0;
}
