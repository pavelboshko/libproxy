#include "proxy_proto.h"
#include "callbacks_mediator.h"
#include <httpxx/http.hpp>
#include "base64.h"
#include <iostream>
#include <sstream>
#include <iconv.h>
#include <chrono>
#include <codecvt>
#include <locale>
#include <unistd.h>
#include <string.h>
#include <algorithm>
#include "crypto/des.h"
#include "crypto/md4.h"
#include "crypto/md5.h"
#include "log.h"

using namespace libproxy;

class NTLNFsm
{
public:
	enum Event {
		SENT_CONNECT,
		HTTP_STATUS_200,
		HTTP_STATUS_401,
		HTTP_STATUS_407,
		HTTP_STATUS_5xx,
		HTTP_STATUS_OTHER
	};

	enum State {
		AUTHETICATION,
		SIGNING,
		SEALING,
		AUTHETICATION_PASS,
		AUTHETICATION_FAIL
	};

	typedef  std::function<void(State old, State current)> onStateChange_t;

	NTLNFsm() : _state(AUTHETICATION){

	}

	static std::string EventToStr(Event e) {
		switch (e) {
		case SENT_CONNECT: return "SENT_CONNECT";
		case HTTP_STATUS_200: return "HTTP_STATUS_200";
		case HTTP_STATUS_401: return "HTTP_STATUS_401";
		case HTTP_STATUS_407: return "HTTP_STATUS_407";
		case HTTP_STATUS_5xx: return "HTTP_STATUS_5xx";
		default:
			throw std::runtime_error("");
			break;
		}
	}

	static std::string StateToStr(State s) {
		switch (s) {
		case AUTHETICATION: return "AUTHETICATION";
		case SIGNING: return "SIGNING";
		case SEALING: return "SEALING";
		case AUTHETICATION_PASS: return "AUTHETICATION_PASS";
		case AUTHETICATION_FAIL: return "AUTHETICATION_FAIL";
		default:
			throw std::runtime_error("");
			break;
		}
	}

	template<typename... Params>
	void onEvent(Event e, Params... args) {
		switch (_state) {
		case AUTHETICATION:
			switch (e) {
			case SENT_CONNECT:
				setState(SIGNING);
				break;
			default:
				break;
			}
			break;
		case SIGNING:
			switch (e) {
			case HTTP_STATUS_200:
				setState(AUTHETICATION_PASS);
				break;
			case HTTP_STATUS_401:
			case HTTP_STATUS_5xx:
			case HTTP_STATUS_OTHER:
				setState(AUTHETICATION_FAIL);
				break;
			case HTTP_STATUS_407:
				setState(SEALING);
				break;
			default:
				break;
			}
			break;
		case SEALING:
			switch (e) {
			case HTTP_STATUS_200:
				setState(AUTHETICATION_PASS);
				break;
			default:
				setState(AUTHETICATION_FAIL);
				break;
			}
			break;
		case AUTHETICATION_PASS:
			break;
		case AUTHETICATION_FAIL:
			break;
		default:
			throw std::runtime_error("");
			break;
		}
	}

	void setState(const State &state)  {
		auto old(_state);
		if(old != state) {
			_state = state;
			_onStateChange(old, _state);
		}
	}

	void setOnStateChange(const onStateChange_t fn) {
		_onStateChange = fn;
	}

private:
	State _state;
	onStateChange_t _onStateChange;
};

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

static inline bool ucnvConvert(const char *enc_from, const char *enc_to,
							   const std::vector<char> &from, std::string* const to)
{
	if (from.empty()) {
		to->clear();
		return true;
	}

	unsigned int maxOutSize = from.size() * 3 + 1;
	std::vector<char> outBuf(maxOutSize);

	iconv_t c = iconv_open(enc_to, enc_from);
	libproxyAssert(c != NULL);
	char* from_ptr = const_cast<char*>(from.data());
	char* to_ptr = &outBuf[0];

	size_t inleft = from.size(), outleft = maxOutSize;
	size_t n = iconv(c, &from_ptr, &inleft, &to_ptr, &outleft);
	bool success = true;
	if (n == (size_t)-1) {
		success = false;
		libproxyAssert(false);
	}

	if (success)
		to->assign(&outBuf[0], maxOutSize - outleft);

	iconv_close(c);

	return success;
}

static inline bool convertUtf8ToUtf16Le(const std::vector<char> &from, std::string* const to)
{ return ucnvConvert("UTF-8", "UTF-16LE", from, to); }

void tranformToUTF16(std::string & str) {
	std::string en_utf16le;
	convertUtf8ToUtf16Le(std::vector<char>(str.begin(), str.end()),  &en_utf16le);
	str = en_utf16le;
}



class protoNTLM : public IProxyProto
{
public:
	protoNTLM () {

		LIBPROXY_TRACE_D("create NTLM proto");

		_fsm.setOnStateChange([this](NTLNFsm::State old, NTLNFsm::State current) {
			LIBPROXY_TRACE_D( NTLNFsm::StateToStr(old), " -> ", NTLNFsm::StateToStr(current));

			switch (current) {
			case NTLNFsm::State::SEALING:
				if(parseRcvChallengeMessage()) {
					_httpxx_response.reset_buffers();
					_httpxx_response.clear();
					_httpxx_response.clear_body();
					auto domain = std::string(_uc.domain);
					auto login = std::string(_uc.login);
					char chostname[1024] = { 0 };
					gethostname(chostname, 1023);
					auto hostname = std::string(chostname);
					sendFinalMessage(domain, login, hostname);
				}
				break;
			case NTLNFsm::State::AUTHETICATION_PASS:
				ICallbackMediator::getMediator()->sendAuthenticationStatus(true);
				break;
			case NTLNFsm::State::AUTHETICATION_FAIL:
				ICallbackMediator::getMediator()->sendAuthenticationStatus(false);
				break;
			default:
				break;
			}
		});
	}


	void start() override {
		ICallbackMediator::getMediator()->getCredsParams(_uc, _cp);
		sendInitMessage();
		_fsm.onEvent(NTLNFsm::Event::SENT_CONNECT);
	}

	void insert(const char *s, size_t length) override {

		auto data = reinterpret_cast<const char*>(s);
		std::size_t size = length;
		std::size_t used = 0;
		std::size_t pass = 0;
		while ((used < size) && !_httpxx_response.complete()) {
			used += _httpxx_response.feed(data + used, size-used);
		}
		// ^^^magic from httpx lib, but it`s works!


		if(_httpxx_response.complete()) {
			_fsm.onEvent(handleHttpHeaderReady());
		} else {
			if(_httpxx_response.status() == 200) {
				_fsm.onEvent(NTLNFsm::Event::HTTP_STATUS_200);
				return;
			}
			ICallbackMediator::getMediator()->requireMoreData();
		}
	}

	NTLNFsm::Event handleHttpHeaderReady()
	{
		auto code = _httpxx_response.status();
		LIBPROXY_TRACE_D("handle http code: ", code);

		switch (code) {
		case 200: return NTLNFsm::Event::HTTP_STATUS_200;
		case 401: return NTLNFsm::Event::HTTP_STATUS_401;
		case 407: return NTLNFsm::Event::HTTP_STATUS_407;
		default:
			switch (code / 100) {
			case 5: return NTLNFsm::Event::HTTP_STATUS_5xx;
			default: return NTLNFsm::Event::HTTP_STATUS_OTHER;
			}
			break;
		}

	}

	std::string GenerateHttpRequest(std::string ntlm_base64_struct, const std::string & serverHost, const std::string & serverPort) {
		std::stringstream ss;
		ss << "CONNECT " << serverHost << ":" << serverPort << " HTTP/1.1\r\n"
		   << "Host: " << serverHost << ":" << serverPort<< "\r\n"
		   << "Proxy-Connection: keep-alive " << "\r\n"
		   << "Proxy-Authorization: NTLM "
		   << ntlm_base64_struct << "\r\n"
		   << "\r\n";
		return ss.str();
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
		std::generate_n(data, size, std::rand);
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

		std::string ntlmHashCalc = ntlmHash(passw);


		legacy::MD5_CTX md5;
		legacy::MD5_Init(&md5);
		legacy::MD5_Update(&md5, session_nonce.data(), session_nonce.size());
		uint8_t session_nonce_hash[16];
		uint8_t sessionHash[8];
		legacy::MD5_Final(session_nonce_hash, &md5);
		::memcpy(sessionHash, session_nonce_hash, sizeof(sessionHash));

		uint8_t nt_resp[24];
		bzero(nt_resp, sizeof(nt_resp));
		calc_resp((unsigned char*) ntlmHashCalc.data(), (unsigned char*) sessionHash, nt_resp);
		NtResponse.append((char*) &nt_resp[0], sizeof(nt_resp));
	}


	void sendInitMessage() {
		type_1_message_t type_1_message;
		memset((void*)&type_1_message, 0, sizeof(type_1_message));
		std::string buff, buff_encode;

		strcpy((char*)&type_1_message.protocol, "NTLMSSP");
		type_1_message.type = NTLMSSP_NEGOTIATE;
		type_1_message.flags = NegotiateUnicode |		 //0x88207;
				NegotiateOEM |
				NegotiateNTLM |
				RequestTarget |
				NegotiateNTLM2Key |
				NegotiateAlwaysSign;

		buff.append((char*)&type_1_message, sizeof(type_1_message));


		buff_encode = base64_encode((uint8_t*)buff.data(), buff.size());

		std::string write_str = GenerateHttpRequest(buff_encode, _cp._remoteHost, std::to_string(_cp._remotePort));
		ICallbackMediator::getMediator()->writeToProxySocket(write_str);
		ICallbackMediator::getMediator()->requireMoreData();
	}

	void sendFinalMessage(std::string & domain, std::string & login, std::string & hostname) {
		std::string buff, buff_encode;
		type_3_message_t type_3_message;
		memset((void*)&type_3_message, 0, sizeof(type_3_message));
		strcpy((char*)&type_3_message.protocol, "NTLMSSP");

		tranformToUTF16(domain);
		tranformToUTF16(login);
		tranformToUTF16(hostname);

		type_3_message.type = NTLMSSP_AUTH;
		type_3_message.flags = NegotiateUnicode |		 ////0x88205;;
				NegotiateNTLM |
				RequestTarget |
				NegotiateNTLM2Key |
				NegotiateAlwaysSign;

		type_3_message.dom_len_1 = domain.size();
		type_3_message.dom_len_2 =	domain.size();
		type_3_message.dom_off = 0x40;
		type_3_message.user_len_1 = login.size();
		type_3_message.user_len_2 = login.size();
		type_3_message.user_off = (type_3_message.dom_off + type_3_message.dom_len_1);
		type_3_message.host_len_1 = hostname.size();
		type_3_message.host_len_2 = hostname.size();
		type_3_message.host_off = (type_3_message.user_off + type_3_message.user_len_1);
		type_3_message.lm_resp_len_1 = 0x18;
		type_3_message.lm_resp_len_2 = 0x18;
		type_3_message.lm_resp_off = (type_3_message.host_off + type_3_message.host_len_1);
		type_3_message.nt_resp_len_1 = 0x18;
		type_3_message.nt_resp_len_2 = 0x18;
		type_3_message.nt_resp_off = (type_3_message.lm_resp_off + type_3_message.lm_resp_len_1);
		buff.append((char*)&type_3_message, sizeof(type_3_message));
		buff.append(domain);
		buff.append(login);
		buff.append(hostname);

		getNTLM2SessionResponse(_uc.password, (uint8_t*)nonce.c_str(), nonce.size(), lm_resp, nt_resp);

		buff.append(lm_resp);
		buff.append(nt_resp);
		type_3_message.msg_len = buff.size();

		buff_encode = base64_encode((uint8_t*)buff.data(), buff.size());
		std::string write_str = GenerateHttpRequest(buff_encode, _cp._remoteHost, std::to_string(_cp._remotePort));

		ICallbackMediator::getMediator()->writeToProxySocket(write_str);
		ICallbackMediator::getMediator()->requireMoreData();
	}

	std::vector<std::string> split (std::string s, std::string delimiter) {
		size_t pos_start = 0, pos_end, delim_len = delimiter.length();
		std::string token;
		std::vector<std::string> res;

		while ((pos_end = s.find (delimiter, pos_start)) != std::string::npos) {
			token = s.substr (pos_start, pos_end - pos_start);
			pos_start = pos_end + delim_len;
			res.push_back (token);
		}

		res.push_back (s.substr (pos_start));
		return res;
	}

	bool parseRcvChallengeMessage() {
		std::string buff_decode, ntlm_data;
		auto proxy_auth_str = _httpxx_response.header("Proxy-Authenticate");
		LIBPROXY_TRACE_D("proxy_auth_proto ", proxy_auth_str);

		auto elems = split(proxy_auth_str, " ");

		if(elems.size() == 2 && elems[0] == "NTLM") {
			buff_decode = base64_decode(elems[1]);

			if(buff_decode.size() >= sizeof(type_2_message_t)) {
				LIBPROXY_TRACE_E("");
				type_2_message_t * type_2_message = (type_2_message_t *)buff_decode.data();

				if(type_2_message->type != NTLMSSP_CHALLENGE) {
					LIBPROXY_TRACE_E("");
					_fsm.onEvent(NTLNFsm::Event::HTTP_STATUS_5xx);
					return false;
				}

				nonce = std::string((char*)type_2_message->nonce, sizeof(type_2_message->nonce));
				LIBPROXY_TRACE_D("Magic:",  std::string((char*)type_2_message->protocol));
			}
			else {
				LIBPROXY_TRACE_E("");
				_fsm.onEvent(NTLNFsm::Event::HTTP_STATUS_5xx);
				return false;
			}

		} else {
			LIBPROXY_TRACE_E("");
			_fsm.onEvent(NTLNFsm::Event::HTTP_STATUS_5xx);
			return false;
		}
		return true;
	}


	userCreds _uc;
	connectionParams _cp;
	std::string login, domain, passw, hostname, nonce;
	std::string lm_resp, nt_resp;
	http::BufferedResponse _httpxx_response;
	NTLNFsm _fsm;
};

PProxyProto IProxyProto::createNTLM()
{
	return std::make_shared<protoNTLM>();
}

