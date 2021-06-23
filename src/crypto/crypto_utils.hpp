/*
 * crypto_utils.hpp
 *
 *  Created on: Oct 24, 2018
 *      Author: pbozhko
 */

#pragma once

#include <string.h>
#include <assert.h>
#include <string>
#include "md4.h"
#include "md5.h"
#include "des.h"
#include "sc_log.h"


static const std::string table_base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "abcdefghijklmnopqrstuvwxyz"
                "0123456789+/";

static inline
bool is_base64(unsigned char c)  {
        return (::isalnum(c) || (c == '+') || (c == '/'));
}

static inline
std::string base64_encode(const uint8_t * buf, size_t bufLen) {
        std::string ret;
        int i = 0;
        int j = 0;
        uint8_t char_array_3[3];
        uint8_t char_array_4[4];

        while (bufLen--) {
                char_array_3[i++] = *(buf++);
                if (i == 3) {
                        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
                        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
                        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
                        char_array_4[3] = char_array_3[2] & 0x3f;

                        for (i = 0; (i < 4); i++) {
                                ret += table_base64_chars[char_array_4[i]];
                        }

                        i = 0;
                }
        }

        if (i) {
                for (j = i; j < 3; j++) {
                        char_array_3[j] = '\0';
                }

                char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
                char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
                char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
                char_array_4[3] = char_array_3[2] & 0x3f;

                for (j = 0; (j < i + 1); j++) {
                        ret += table_base64_chars[char_array_4[j]];
                }

                while ((i++ < 3)) {
                        ret += '=';
                }

        }
        return ret;
}

static inline
std::string base64_decode(std::string const& encoded_string) {
        int in_len = encoded_string.size();
        int i = 0;
        int j = 0;
        int in_ = 0;
        unsigned char char_array_4[4], char_array_3[3];
        std::string ret;

        while (in_len-- && (encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
                char_array_4[i++] = encoded_string[in_];
                in_++;
                if (i == 4) {
                        for (i = 0; i < 4; i++) {
                                char_array_4[i] = table_base64_chars.find(char_array_4[i]);
                        }

                        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
                        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
                        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

                        for (i = 0; (i < 3); i++) {
                                ret += char_array_3[i];
                        }
                        i = 0;
                }
        }

        if (i) {
                for (j = i; j < 4; j++) {
                        char_array_4[j] = 0;
                }

                for (j = 0; j < 4; j++) {
                        char_array_4[j] = table_base64_chars.find(char_array_4[j]);
                }
                char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
                char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
                char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

                for (j = 0; (j < i - 1); j++) {
                        ret += char_array_3[j];
                }
        }

        return ret;
}

static inline
void setup_des_key(unsigned char * key_56, void * schedule_key) {
        uint8_t key[8] = { 0 };
        legacy::mbedtls_des_context * sk
                = reinterpret_cast<legacy::mbedtls_des_context*>(schedule_key);

        key[0] = key_56[0];
        key[1] = ((key_56[0] << 7) & 0xFF) | (key_56[1] >> 1);
        key[2] = ((key_56[1] << 6) & 0xFF) | (key_56[2] >> 2);
        key[3] = ((key_56[2] << 5) & 0xFF) | (key_56[3] >> 3);
        key[4] = ((key_56[3] << 4) & 0xFF) | (key_56[4] >> 4);
        key[5] = ((key_56[4] << 3) & 0xFF) | (key_56[5] >> 5);
        key[6] = ((key_56[5] << 2) & 0xFF) | (key_56[6] >> 6);
        key[7] = (key_56[6] << 1) & 0xFF;
        legacy::mbedtls_des_key_set_parity(key);
        legacy::mbedtls_des_setkey_enc( sk, key );
}

static inline
void getLanManagerResp(const unsigned char * rand, size_t rand_size,
                std::string & LanManagerResp) {
        char tail[16] = { 0 };
        LanManagerResp.append((char*) &rand[0], (char*) &rand[0] + rand_size);
        LanManagerResp.append((char*) &tail[0], (char*) &tail[0] + sizeof(tail));
}

static inline
void calc_resp(unsigned char *keys, unsigned char *plaintext, unsigned char *results) {

        legacy::mbedtls_des_context ctx;
        legacy::mbedtls_des_init(&ctx);

        setup_des_key(keys, (void*)&ctx);
        legacy::mbedtls_des_crypt_ecb( &ctx, plaintext, results );
        setup_des_key(keys + 7, (void*)&ctx);
        legacy::mbedtls_des_crypt_ecb(&ctx, plaintext, (uint8_t*)(&results[0]+8));
        setup_des_key(keys + 14, (void*)&ctx);
        legacy::mbedtls_des_crypt_ecb(&ctx, plaintext, (uint8_t*)(&results[0]+16));
        mbedtls_des_free(&ctx);
}

static inline
std::string ntlmHash(const std::string & password) {
        std::string unicode_passwd;
        for (auto & v : password) {
                unicode_passwd.push_back(v);
                unicode_passwd.push_back((char) 0);
        }

        uint8_t passw_hash[21];
        bzero(passw_hash, sizeof(passw_hash));
        legacy::MD4_CTX context;
        legacy::MD4_Init(&context);
        legacy::MD4_Update(&context, unicode_passwd.data(), unicode_passwd.size());
        legacy::MD4_Final(passw_hash, &context);
        unicode_passwd.clear();
        return std::string((char*) &passw_hash[0], (char*) &passw_hash[0] + sizeof(passw_hash));
}

static inline
void fill_random(uint8_t * data, size_t size) {
#ifdef __APPLE__
     arc4random_buf(data, size);
#else
     std::ifstream urandom("/dev/urandom", std::ios::in|std::ios::binary); //Open stream
     if(urandom) {
         urandom.read(reinterpret_cast<char*>(data), size);
     } else {
         sc_log::err("sccryptRandom::generate can't open  /dev/urandom");
         assert(false);
     }
     urandom.close();
#endif
}

static inline
void getNTLM2SessionResponse(const std::string & passw, const uint8_t * nonce,
                size_t nonce_len, std::string & LanManagerResp, std::string & NtResponse) {
        unsigned char client_rand[8];

        fill_random(client_rand, sizeof(client_rand));

        getLanManagerResp(client_rand, sizeof(client_rand), LanManagerResp);
        std::string session_nonce;
        session_nonce.append((char*) nonce, (char*) nonce + nonce_len);
        session_nonce.append((char*) &client_rand[0],
                        (char*) &client_rand[0] + sizeof(client_rand));
#if 0
        sc_log::buf("session_nonce: ", session_nonce.data(), session_nonce.size());
#endif
        std::string ntlmHashCalc = ntlmHash(passw);
#if 0
        sc_log::buf("ntlmHash: ", (char*)ntlmHashCalc.data(), ntlmHashCalc.size());
#endif

        legacy::MD5_CTX md5;
        legacy::MD5_Init(&md5);
        legacy::MD5_Update(&md5, session_nonce.data(), session_nonce.size());
        uint8_t session_nonce_hash[16];
        uint8_t sessionHash[8];
        legacy::MD5_Final(session_nonce_hash, &md5);
        ::memcpy(sessionHash, session_nonce_hash, sizeof(sessionHash));
#if 0
        sc_log::buf("sessionHash: ", (char*)sessionHash, sizeof(sessionHash));
#endif
        uint8_t nt_resp[24];
        bzero(nt_resp, sizeof(nt_resp));
        calc_resp((unsigned char*) ntlmHashCalc.data(), (unsigned char*) sessionHash, nt_resp);
        NtResponse.append((char*) &nt_resp[0], sizeof(nt_resp));
}


