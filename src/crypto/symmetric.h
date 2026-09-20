#pragma once
#include "common/core.h"
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
namespace shkr {
inline void random_bytes(void *p, size_t n) {
    auto b = static_cast<uint8_t *>(p);
    while (n) {
        size_t m = std::min(n, size_t(1 << 28));
        require(RAND_bytes(b, int(m)) == 1, "RAND_bytes failed");
        b += m;
        n -= m;
    }
}
inline Words random_words(uint64_t n) {
    Words w(word_count(n));
    random_bytes(w.data(), w.size() * 8);
    mask_tail(w, n);
    return w;
}
inline Seed random_seed() {
    Seed s;
    random_bytes(s.data(), s.size());
    return s;
}
inline Digest sha256(const Bytes &x) {
    Digest d;
    SHA256(x.data(), x.size(), d.data());
    return d;
}
inline std::string hex_digest(const Digest &digest) {
    static constexpr char h[] = "0123456789abcdef";
    std::string out(64, '0');
    for (size_t i = 0; i < digest.size(); i++) {
        out[2 * i] = h[digest[i] >> 4];
        out[2 * i + 1] = h[digest[i] & 15];
    }
    return out;
}
inline std::string sha256_hex(const void *data, size_t size) {
    Digest d;
    SHA256(static_cast<const uint8_t *>(data), size, d.data());
    return hex_digest(d);
}
inline std::string sha256_hex(const Bytes &data) {
    return sha256_hex(data.data(), data.size());
}
inline std::string sha256_hex(const Words &data) {
    return sha256_hex(data.data(), data.size() * 8);
}
inline void prg_into(const Seed &key, const Bytes &context, uint64_t n, uint64_t *out) {
    auto iv = sha256(context);
    const size_t count = word_count(n);
    std::fill(out, out + count, uint64_t(0));
    auto ctx = EVP_CIPHER_CTX_new();
    require(ctx, "EVP allocation");
    int len = 0;
    require(EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), nullptr, key.data(), iv.data()) == 1,
            "PRG init");
    require(EVP_EncryptUpdate(ctx, (uint8_t *)out, &len, (const uint8_t *)out, count * 8) == 1,
            "PRG update");
    EVP_CIPHER_CTX_free(ctx);
    if (count)
        out[count - 1] &= tail_mask(n);
}
inline Words prg(const Seed &key, const Bytes &context, uint64_t n) {
    Words out(word_count(n));
    prg_into(key, context, n, out.data());
    return out;
}
inline Bytes hint_context(uint64_t epoch, uint64_t token, uint32_t j) {
    Writer w;
    w.text("HINT");
    w.u64(epoch);
    w.u64(token);
    w.u32(j);
    return w.b;
}
inline Bytes ot_context(uint64_t run, uint32_t server, uint32_t leaf, uint32_t s) {
    Writer w;
    w.text("OT-LONG");
    w.u64(run);
    w.u32(server);
    w.u32(leaf);
    w.u32(s);
    return w.b;
}
inline Bytes payload_input(uint64_t epoch, uint64_t n) {
    Writer w;
    w.text("SHPR-PAYLOAD");
    w.u64(epoch);
    w.u64(n);
    return w.b;
}
inline Digest payload_key(const Digest &z0, const Digest &z1, uint64_t epoch, uint64_t n) {
    Writer ikm;
    ikm.raw(z0.data(), 32);
    ikm.raw(z1.data(), 32);
    Writer salt;
    salt.u64(epoch);
    Writer info;
    info.text("SHPR-PAYLOAD-KEY");
    info.u64(n);
    Digest out;
    size_t size = 32;
    auto ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    require(ctx, "HKDF context");
    require(EVP_PKEY_derive_init(ctx) > 0 && EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) > 0 &&
                EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt.b.data(), salt.b.size()) > 0 &&
                EVP_PKEY_CTX_set1_hkdf_key(ctx, ikm.b.data(), ikm.b.size()) > 0 &&
                EVP_PKEY_CTX_add1_hkdf_info(ctx, info.b.data(), info.b.size()) > 0 &&
                EVP_PKEY_derive(ctx, out.data(), &size) > 0,
            "HKDF failed");
    EVP_PKEY_CTX_free(ctx);
    return out;
}
inline Bytes encrypt_payload(const Digest &key, const uint8_t *plain, size_t n, uint64_t epoch,
                             uint64_t idx) {
    Bytes out(n + 28);
    random_bytes(out.data(), 12);
    Writer ad;
    ad.u64(epoch);
    ad.u64(idx);
    auto c = EVP_CIPHER_CTX_new();
    int l = 0, total = 0;
    require(EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), nullptr, key.data(), out.data()) == 1,
            "GCM init");
    require(EVP_EncryptUpdate(c, nullptr, &l, ad.b.data(), ad.b.size()) == 1, "GCM AD");
    require(EVP_EncryptUpdate(c, out.data() + 12, &l, plain, n) == 1, "GCM encrypt");
    total = l;
    require(EVP_EncryptFinal_ex(c, out.data() + 12 + total, &l) == 1, "GCM final");
    require(EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, 16, out.data() + 12 + n) == 1, "GCM tag");
    EVP_CIPHER_CTX_free(c);
    return out;
}
inline Bytes decrypt_payload(const Digest &key, const Bytes &entry, uint64_t epoch, uint64_t idx) {
    require(entry.size() >= 28, "short AEAD entry");
    size_t n = entry.size() - 28;
    Bytes out(n);
    Writer ad;
    ad.u64(epoch);
    ad.u64(idx);
    auto c = EVP_CIPHER_CTX_new();
    int l = 0, total = 0;
    require(EVP_DecryptInit_ex(c, EVP_aes_256_gcm(), nullptr, key.data(), entry.data()) == 1,
            "GCM init");
    EVP_DecryptUpdate(c, nullptr, &l, ad.b.data(), ad.b.size());
    require(EVP_DecryptUpdate(c, out.data(), &l, entry.data() + 12, n) == 1, "GCM decrypt");
    total = l;
    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, 16, (void *)(entry.data() + 12 + n));
    int ok = EVP_DecryptFinal_ex(c, out.data() + total, &l);
    EVP_CIPHER_CTX_free(c);
    require(ok == 1, "AEAD authentication failed");
    return out;
}
}
