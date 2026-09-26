#pragma once
#include "common/core.h"
#include "crypto/symmetric.h"
#include <ENCRYPTO_utils/connection.h>
#include <ENCRYPTO_utils/socket.h>
#include <ENCRYPTO_utils/crypto/crypto.h>
#include <ENCRYPTO_utils/sndthread.h>
#include <ENCRYPTO_utils/rcvthread.h>
#include <kk-ot-ext-snd.h>
#include <kk-ot-ext-rec.h>
#include <xormasking.h>
namespace shks {
class KK13 {
    Seed init_seed_ = random_seed();
    crypto crypt_{128, init_seed_.data()};
    CLock lock_;
    std::unique_ptr<CSocket> socket_;
    std::unique_ptr<SndThread> snd_thread_;
    std::unique_ptr<RcvThread> rcv_thread_;
    std::unique_ptr<KKOTExtSnd> sender_;
    std::unique_ptr<KKOTExtRec> receiver_;
    uint32_t p_;

  public:
    KK13(bool sender, const std::string &host, uint16_t port, uint32_t p) : p_(p) {
        require(pow2(p) && p >= 2 && p <= 256,
                "KK13 native arity supports powers of two from 2 through 256");
        socket_ = sender ? Listen(host, port) : Connect(host, port);
        require(bool(socket_), "KK13 socket setup failed");
        snd_thread_ = std::make_unique<SndThread>(socket_.get(), &lock_);
        rcv_thread_ = std::make_unique<RcvThread>(socket_.get(), &lock_);
        rcv_thread_->Start();
        snd_thread_->Start();
        if (sender) {
            sender_ = std::make_unique<KKOTExtSnd>(&crypt_, rcv_thread_.get(), snd_thread_.get(), 1,
                                                   false);
            sender_->ComputeBaseOTs(ECC_FIELD);
        } else {
            receiver_ = std::make_unique<KKOTExtRec>(&crypt_, rcv_thread_.get(), snd_thread_.get(),
                                                     1, false);
            receiver_->ComputeBaseOTs(ECC_FIELD);
        }
    }
    ~KK13() {
        if (std::uncaught_exceptions()) {
            sender_.release();
            receiver_.release();
            snd_thread_.release();
            rcv_thread_.release();
            socket_.release();
            return;
        }
        sender_.reset();
        receiver_.reset();
        snd_thread_.reset();
        rcv_thread_.reset();
    }
    std::pair<uint64_t, uint64_t> counters() const {
        return {socket_->getSndCnt(), socket_->getRcvCnt()};
    }
    std::vector<Seed> send(size_t count) {
        require(bool(sender_), "not KK13 sender");
        std::vector<std::unique_ptr<CBitVector>> vals;
        std::vector<CBitVector *> pointers;
        for (uint32_t s = 0; s < p_; s++) {
            vals.push_back(std::make_unique<CBitVector>());
            vals.back()->Create(count + 8, 128);
            pointers.push_back(vals.back().get());
        }
        XORMasking mask(128);
        require(sender_->send(count, 128, p_, pointers.data(), Snd_R_OT, Rec_OT, 1, &mask),
                "KK13 send failed");
        std::vector<Seed> seeds(count * p_);
        for (size_t i = 0; i < count; i++)
            for (uint32_t s = 0; s < p_; s++)
                memcpy(seeds[i * p_ + s].data(), pointers[s]->GetArr() + 16 * i, 16);
        return seeds;
    }
    std::vector<Seed> receive(const std::vector<uint32_t> &choice) {
        require(bool(receiver_), "not KK13 receiver");
        unsigned bits = 0;
        while ((1u << bits) < p_)
            bits++;
        CBitVector choices, response;
        choices.Create((choice.size() + 8) * bits);
        choices.Reset();
        response.Create(choice.size() + 8, 128);
        response.Reset();
        for (size_t i = 0; i < choice.size(); i++) {
            require(choice[i] < p_, "KK13 choice out of range");
            choices.Set<uint32_t>(choice[i], i * bits, bits);
        }
        XORMasking mask(128);
        require(receiver_->receive(choice.size(), 128, p_, &choices, &response, Snd_R_OT, Rec_OT, 1,
                                   &mask),
                "KK13 receive failed");
        std::vector<Seed> out(choice.size());
        for (size_t i = 0; i < out.size(); i++)
            memcpy(out[i].data(), response.GetArr() + 16 * i, 16);
        return out;
    }
};
}
