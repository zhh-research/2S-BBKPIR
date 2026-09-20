#pragma once
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>
#include <time.h>
#include <nlohmann/json.hpp>

namespace shkr {
using Json = nlohmann::json;
using Bytes = std::vector<uint8_t>;
using Seed = std::array<uint8_t, 16>;
using Digest = std::array<uint8_t, 32>;
namespace fs = std::filesystem;
inline void require(bool ok, const std::string &msg) {
    if (!ok)
        throw std::runtime_error(msg);
}
template <class T> struct AlignedAllocator {
    using value_type = T;
    AlignedAllocator() = default;
    template <class U> AlignedAllocator(const AlignedAllocator<U> &) {
    }
    T *allocate(size_t n) {
        void *p = nullptr;
        if (posix_memalign(&p, 64, std::max(size_t(64), n * sizeof(T))))
            throw std::bad_alloc();
        return static_cast<T *>(p);
    }
    void deallocate(T *p, size_t) {
        free(p);
    }
    template <class U> bool operator==(const AlignedAllocator<U> &) const {
        return true;
    }
    template <class U> bool operator!=(const AlignedAllocator<U> &) const {
        return false;
    }
};
using Words = std::vector<uint64_t, AlignedAllocator<uint64_t>>;
inline uint64_t word_count(uint64_t n) {
    return (n + 63) / 64;
}
inline uint64_t tail_mask(uint64_t n) {
    return n % 64 ? (uint64_t(1) << (n % 64)) - 1 : ~uint64_t(0);
}
inline void mask_tail(Words &a, uint64_t n) {
    if (!a.empty())
        a.back() &= tail_mask(n);
}
inline bool pow2(uint64_t x) {
    return x && !(x & (x - 1));
}
inline uint64_t next_pow2(uint64_t x) {
    uint64_t r = 1;
    while (r < x) {
        require(r < (1ull << 62), "power-of-two overflow");
        r *= 2;
    }
    return r;
}
inline double cpu_ms() {
    timespec t{};
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t);
    return t.tv_sec * 1000.0 + t.tv_nsec / 1e6;
}
using Clock = std::chrono::steady_clock;
inline double elapsed(Clock::time_point start) {
    return std::chrono::duration<double, std::milli>(Clock::now() - start).count();
}
struct Writer {
    Bytes b;
    void u32(uint32_t x) {
        for (int i = 0; i < 4; i++)
            b.push_back(uint8_t(x >> (8 * i)));
    }
    void u64(uint64_t x) {
        for (int i = 0; i < 8; i++)
            b.push_back(uint8_t(x >> (8 * i)));
    }
    void raw(const void *p, size_t n) {
        if (n) {
            auto v = static_cast<const uint8_t *>(p);
            b.insert(b.end(), v, v + n);
        }
    }
    void text(const std::string &x) {
        raw(x.data(), x.size());
    }
    void blob(const Bytes &x) {
        u64(x.size());
        raw(x.data(), x.size());
    }
};
struct Reader {
    const uint8_t *p;
    size_t size, pos = 0;
    explicit Reader(const Bytes &b) : p(b.data()), size(b.size()) {
    }
    Reader(const void *x, size_t n) : p(static_cast<const uint8_t *>(x)), size(n) {
    }
    void check(size_t n) {
        require(n <= size - pos, "truncated binary message");
    }
    uint32_t u32() {
        check(4);
        uint32_t x = 0;
        for (int i = 0; i < 4; i++)
            x |= uint32_t(p[pos++]) << (i * 8);
        return x;
    }
    uint64_t u64() {
        check(8);
        uint64_t x = 0;
        for (int i = 0; i < 8; i++)
            x |= uint64_t(p[pos++]) << (i * 8);
        return x;
    }
    void raw(void *out, size_t n) {
        check(n);
        if (n)
            memcpy(out, p + pos, n);
        pos += n;
    }
    Bytes blob() {
        auto n = u64();
        check(n);
        Bytes x(p + pos, p + pos + n);
        pos += n;
        return x;
    }
    void end() {
        require(pos == size, "trailing bytes in message");
    }
};
inline Bytes bytes(const Words &x) {
    Bytes b(x.size() * 8);
    memcpy(b.data(), x.data(), b.size());
    return b;
}
inline Words words(const Bytes &x, size_t expected) {
    require(x.size() == expected * 8, "bitmap wire size mismatch");
    Words w(expected);
    memcpy(w.data(), x.data(), x.size());
    return w;
}
inline Json read_json(const fs::path &p) {
    std::ifstream f(p);
    require(bool(f), "cannot read " + p.string());
    Json j;
    f >> j;
    return j;
}
inline void write_json(const fs::path &p, const Json &j) {
    fs::create_directories(p.parent_path());
    std::ofstream f(p);
    require(bool(f), "cannot write " + p.string());
    f << j.dump(2) << '\n';
}
struct Header {
    uint64_t N = 0;
    uint32_t M = 0, p = 0, L = 0;
    uint64_t count = 0, W = 0;
    Bytes encode(const std::string &magic) const {
        require(magic.size() == 8, "magic size");
        Writer w;
        w.text(magic);
        w.u32(1);
        w.u64(N);
        w.u32(M);
        w.u32(p);
        w.u32(L);
        w.u64(count);
        w.u64(W);
        return w.b;
    }
    static Header decode(const Bytes &b, const std::string &magic) {
        Reader r(b);
        char m[8];
        r.raw(m, 8);
        require(std::string(m, 8) == magic, "artifact magic mismatch");
        require(r.u32() == 1, "artifact version mismatch");
        Header h;
        h.N = r.u64();
        h.M = r.u32();
        h.p = r.u32();
        h.L = r.u32();
        h.count = r.u64();
        h.W = r.u64();
        r.end();
        return h;
    }
};
inline void save_binary(const fs::path &p, const Header &h, const std::string &magic,
                        const void *data, size_t n) {
    fs::create_directories(p.parent_path());
    std::ofstream f(p, std::ios::binary);
    require(bool(f), "cannot write " + p.string());
    auto b = h.encode(magic);
    f.write((const char *)b.data(), b.size());
    f.write((const char *)data, n);
    require(bool(f), "binary write failure");
}
inline Bytes load_binary(const fs::path &p, const Header &h, const std::string &magic, size_t n) {
    require(fs::file_size(p) == 48 + n, "artifact size mismatch: " + p.string());
    std::ifstream f(p, std::ios::binary);
    Bytes head(48);
    f.read((char *)head.data(), 48);
    require(head == h.encode(magic), "artifact header mismatch: " + p.string());
    Bytes b(n);
    f.read((char *)b.data(), n);
    require(bool(f), "binary read failure");
    return b;
}
inline std::vector<uint64_t> support(const Words &x, uint64_t n) {
    std::vector<uint64_t> out;
    for (size_t i = 0; i < x.size(); i++) {
        uint64_t v = x[i];
        while (v) {
            unsigned b = __builtin_ctzll(v);
            uint64_t idx = i * 64 + b;
            if (idx < n)
                out.push_back(idx);
            v &= v - 1;
        }
    }
    return out;
}
}
