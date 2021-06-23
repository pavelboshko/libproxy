#pragma once
#include <stdint.h>

namespace C4_NTLM_AUTH
{

enum ntlmssp_messagetype {
	NTLMSSP_NEGOTIATE = 0x01,
	NTLMSSP_CHALLENGE = 0x02,
	NTLMSSP_AUTH = 0x03
};

enum ntlm_flags {
	NegotiateUnicode = 0x00000001,
	NegotiateOEM = 0x00000002,
	RequestTarget = 0x00000004,
	NegotiateNTLM = 0x00000200,
	NegotiateAlwaysSign = 0x00008000,
	NegotiateNTLM2Key = 0x00080000,
};

typedef struct {
	uint8_t    protocol[8];     // 'N', 'T', 'L', 'M', 'S', 'S', 'P', '\0'
	uint8_t    type;            // 0x01
	uint8_t    zero[3];
	uint32_t   flags;           //
	uint8_t    zero_test[16];
} type_1_message_t;

typedef  struct {
	uint8_t    protocol[8];     // 'N', 'T', 'L', 'M', 'S', 'S', 'P', '\0'
	uint8_t    type;            // 0x02
	uint8_t    zero_1[7];
	uint16_t   msg_len;         // 0x28
	uint8_t    zero_2[2];
	uint16_t   flags;           // 0x8201  // uint16_t
	uint8_t    zero_3[2];
	uint8_t    nonce[8];        // nonce
	uint8_t    zero_4[8];
} type_2_message_t;

typedef  struct {
	uint8_t    protocol[8];     // 'N', 'T', 'L', 'M', 'S', 'S', 'P', '\0'
	uint8_t    type;            // 0x03
	uint8_t    zero_1[3];
	uint16_t   lm_resp_len_1;     // LanManager response length (always 0x18)
	uint16_t   lm_resp_len_2;     // LanManager response length (always 0x18)
	uint16_t   lm_resp_off;     // LanManager response offset
	uint8_t    zero_2[2];
	uint16_t   nt_resp_len_1;     // NT response length (always 0x18)
	uint16_t   nt_resp_len_2;     // NT response length (always 0x18)
	uint16_t   nt_resp_off;     // NT response offset
	uint8_t    zero_3[2];
	uint16_t   dom_len_1;         // domain string length
	uint16_t   dom_len_2;         // domain string length
	uint16_t   dom_off;         // domain string offset (always 0x40)
	uint8_t    zero_4[2];
	uint16_t   user_len_1;        // username string length
	uint16_t   user_len_2;        // username string length
	uint16_t   user_off;        // username string offset
	uint8_t    zero_5[2];
	uint16_t   host_len_1;        // host string length
	uint16_t   host_len_2;        // host string length
	uint16_t   host_off;        // host string offset
	uint8_t    zero_6[6];
	uint16_t   msg_len;         // message length
	uint8_t    zero_7[2];
	uint32_t   flags;           // 0x8201 // uint16_t
	//    byte    dom[*];          // domain string (unicode UTF-16LE)
	//    byte    user[*];         // username string (unicode UTF-16LE)
	//    byte    host[*];         // host string (unicode UTF-16LE)
	//    byte    lm_resp[*];      // LanManager response
	//    byte    nt_resp[*];      // NT response
} type_3_message_t;

}  // namespace C4_NTLM_AUTH
