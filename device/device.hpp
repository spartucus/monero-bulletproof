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

#include "crypto/crypto.h"
#include "crypto/chacha.h"
#include "ringct/rctTypes.h"
#include "cryptonote_config.h"


#ifndef USE_DEVICE_LEDGER
#define USE_DEVICE_LEDGER 1
#endif

#if !defined(HAVE_HIDAPI) 
#undef  USE_DEVICE_LEDGER
#define USE_DEVICE_LEDGER 0
#endif

#if USE_DEVICE_LEDGER
#define WITH_DEVICE_LEDGER
#endif

// forward declaration needed because this header is included by headers in libcryptonote_basic which depends on libdevice
namespace cryptonote
{
    struct account_public_address;
    struct account_keys;
    struct subaddress_index;
    struct tx_destination_entry;
    struct keypair;
}

namespace hw {
    namespace {
        //device funcion not supported
        #define dfns()  \
           throw std::runtime_error(std::string("device function not supported: ")+ std::string(__FUNCTION__) + \
                                    std::string(" (device.hpp line ")+std::to_string(__LINE__)+std::string(").")); \
           return false;
    }

    class device_progress {
    public:
      virtual double progress() const { return 0; }
      virtual bool indeterminate() const { return false; }
    };

    class i_device_callback {
    public:
        virtual void on_button_request(uint64_t code=0) {}
        virtual void on_button_pressed() {}
        virtual boost::optional<epee::wipeable_string> on_pin_request() { return boost::none; }
        virtual boost::optional<epee::wipeable_string> on_passphrase_request(bool on_device) { return boost::none; }
        virtual void on_progress(const device_progress& event) {}
        virtual ~i_device_callback() = default;
    };

    class device {
    protected:
        std::string  name;

    public:

        device(): mode(NONE)  {}
        device(const device &hwdev) {}
        virtual ~device()   {}

        explicit virtual operator bool() const = 0;
        enum device_mode {
            NONE,
            TRANSACTION_CREATE_REAL,
            TRANSACTION_CREATE_FAKE,
            TRANSACTION_PARSE
        };
        enum device_type
        {
          SOFTWARE = 0,
          LEDGER = 1,
          TREZOR = 2
        };


        enum device_protocol_t {
            PROTOCOL_DEFAULT,
            PROTOCOL_PROXY,     // Originally defined by Ledger
            PROTOCOL_COLD,      // Originally defined by Trezor
        };

        /* ======================================================================= */
        /*                              SETUP/TEARDOWN                             */
        /* ======================================================================= */
        virtual bool set_name(const std::string &name) = 0;
        virtual const std::string get_name() const = 0;

        virtual bool set_mode(device_mode mode) { this->mode = mode; return true; }
        virtual device_mode get_mode() const { return mode; }

        virtual device_type get_type() const = 0;

        /* ======================================================================= */
        /*                               TRANSACTION                               */
        /* ======================================================================= */
        virtual rct::key genCommitmentMask(const rct::key &amount_key) = 0;

        virtual bool  ecdhEncode(rct::ecdhTuple & unmasked, const rct::key & sharedSec, bool short_amount) = 0;
        virtual bool  ecdhDecode(rct::ecdhTuple & masked, const rct::key & sharedSec, bool short_amount) = 0;

        virtual bool  mlsag_prehash(const std::string &blob, size_t inputs_size, size_t outputs_size, const rct::keyV &hashes, const rct::ctkeyV &outPk, rct::key &prehash) = 0;
        virtual bool  mlsag_prepare(const rct::key &H, const rct::key &xx, rct::key &a, rct::key &aG, rct::key &aHP, rct::key &rvII) = 0;
        virtual bool  mlsag_prepare(rct::key &a, rct::key &aG) = 0;
        virtual bool  mlsag_hash(const rct::keyV &long_message, rct::key &c) = 0;
        virtual bool  mlsag_sign(const rct::key &c, const rct::keyV &xx, const rct::keyV &alpha, const size_t rows, const size_t dsRows, rct::keyV &ss) = 0;

    protected:
        device_mode mode;
    } ;

    struct reset_mode {
        device& hwref;
        reset_mode(hw::device& dev) : hwref(dev) { }
        ~reset_mode() { hwref.set_mode(hw::device::NONE);}
    };

    class device_registry {
    private:
      std::map<std::string, std::unique_ptr<device>> registry;

    public:
      device_registry();
      bool register_device(const std::string & device_name, device * hw_device);
      device& get_device(const std::string & device_descriptor);
    };

    device& get_device(const std::string & device_descriptor);
    bool register_device(const std::string & device_name, device * hw_device);
}

