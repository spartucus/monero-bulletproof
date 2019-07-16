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




#include "device_default.hpp"
#include "int-util.h"
//#include "cryptonote_basic/account.h" Spartucus
//#include "cryptonote_basic/subaddress_index.h"    Spartucus
//#include "cryptonote_core/cryptonote_tx_utils.h"  Spartucus
#include "ringct/rctOps.h"
#include "misc_log_ex.h"

#define ENCRYPTED_PAYMENT_ID_TAIL 0x8d
#define CHACHA8_KEY_TAIL 0x8c

namespace hw {

    namespace core {

        device_default::device_default() { }

        device_default::~device_default() { }

        /* ===================================================================== */
        /* ===                        Misc                                ==== */
        /* ===================================================================== */
        static inline unsigned char *operator &(crypto::ec_scalar &scalar) {
            return &reinterpret_cast<unsigned char &>(scalar);
        }
        static inline const unsigned char *operator &(const crypto::ec_scalar &scalar) {
            return &reinterpret_cast<const unsigned char &>(scalar);
        }

        /* ======================================================================= */
        /*                              SETUP/TEARDOWN                             */
        /* ======================================================================= */
        bool device_default::set_name(const std::string &name)  {
            this->name = name;
            return true;
        }
        const std::string device_default::get_name()  const {
            return this->name;
        }

        bool  device_default::set_mode(device_mode mode) {
            return device::set_mode(mode);
        }

        rct::key device_default::genCommitmentMask(const rct::key &amount_key) {
            return rct::genCommitmentMask(amount_key);
        }

        bool  device_default::ecdhEncode(rct::ecdhTuple & unmasked, const rct::key & sharedSec, bool short_amount) {
            rct::ecdhEncode(unmasked, sharedSec, short_amount);
            return true;
        }

        bool  device_default::ecdhDecode(rct::ecdhTuple & masked, const rct::key & sharedSec, bool short_amount) {
            rct::ecdhDecode(masked, sharedSec, short_amount);
            return true;
        }

        bool device_default::mlsag_prepare(const rct::key &H, const rct::key &xx,
                                         rct::key &a, rct::key &aG, rct::key &aHP, rct::key &II) {
            rct::skpkGen(a, aG);
            rct::scalarmultKey(aHP, H, a);
            rct::scalarmultKey(II, H, xx);
            return true;
        }
        bool  device_default::mlsag_prepare(rct::key &a, rct::key &aG) {
            rct::skpkGen(a, aG);
            return true;
        }
        bool  device_default::mlsag_prehash(const std::string &blob, size_t inputs_size, size_t outputs_size, const rct::keyV &hashes, const rct::ctkeyV &outPk, rct::key &prehash) {
            prehash = rct::cn_fast_hash(hashes);
            return true;
        }


        bool device_default::mlsag_hash(const rct::keyV &toHash, rct::key &c_old) {
            c_old = rct::hash_to_scalar(toHash);
            return true;
        }

        bool device_default::mlsag_sign(const rct::key &c,  const rct::keyV &xx, const rct::keyV &alpha, const size_t rows, const size_t dsRows, rct::keyV &ss ) {
            CHECK_AND_ASSERT_THROW_MES(dsRows<=rows, "dsRows greater than rows");
            CHECK_AND_ASSERT_THROW_MES(xx.size() == rows, "xx size does not match rows");
            CHECK_AND_ASSERT_THROW_MES(alpha.size() == rows, "alpha size does not match rows");
            CHECK_AND_ASSERT_THROW_MES(ss.size() == rows, "ss size does not match rows");
            for (size_t j = 0; j < rows; j++) {
                sc_mulsub(ss[j].bytes, c.bytes, xx[j].bytes, alpha[j].bytes);
            }
            return true;
        }


        /* ---------------------------------------------------------- */
        static device_default *default_core_device = NULL;
        void register_all(std::map<std::string, std::unique_ptr<device>> &registry) {
            if (!default_core_device) {
                default_core_device = new device_default();
                default_core_device->set_name("default_core_device");

            }
            registry.insert(std::make_pair("default", std::unique_ptr<device>(default_core_device)));
        }


    }

}
