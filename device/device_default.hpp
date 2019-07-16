// Copyright (c) 2017-2019, The Monero Project
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

#pragma once

#include "device.hpp"

namespace hw {

    namespace core {

        void register_all(std::map<std::string, std::unique_ptr<device>> &registry);

        class device_default : public hw::device {
        public:
            device_default();
            ~device_default();

            device_default(const device_default &device) = delete;
            device_default& operator=(const device_default &device) = delete;

            explicit operator bool() const override { return false; };

             /* ======================================================================= */
            /*                              SETUP/TEARDOWN                             */
            /* ======================================================================= */
            bool set_name(const std::string &name) override;
            const std::string get_name() const override;
 
            bool set_mode(device_mode mode) override;

            device_type get_type() const override {return device_type::SOFTWARE;};

            /* ======================================================================= */
            /*                               TRANSACTION                               */
            /* ======================================================================= */

            rct::key genCommitmentMask(const rct::key &amount_key) override;

            bool  ecdhEncode(rct::ecdhTuple & unmasked, const rct::key & sharedSec, bool short_amount) override;
            bool  ecdhDecode(rct::ecdhTuple & masked, const rct::key & sharedSec, bool short_amount) override;

            bool  mlsag_prehash(const std::string &blob, size_t inputs_size, size_t outputs_size, const rct::keyV &hashes, const rct::ctkeyV &outPk, rct::key &prehash) override;
            bool  mlsag_prepare(const rct::key &H, const rct::key &xx, rct::key &a, rct::key &aG, rct::key &aHP, rct::key &rvII) override;
            bool  mlsag_prepare(rct::key &a, rct::key &aG) override;
            bool  mlsag_hash(const rct::keyV &long_message, rct::key &c) override;
            bool  mlsag_sign(const rct::key &c, const rct::keyV &xx, const rct::keyV &alpha, const size_t rows, const size_t dsRows, rct::keyV &ss) override;
        };

    }



}

