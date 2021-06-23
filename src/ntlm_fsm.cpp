#include "ntlm_fsm.h"
#include "legacy/crypto_utils.hpp"
#include <boost/algorithm/string.hpp>

namespace C4_NTLM_AUTH {

template<> State Ntlm_Fsm::processEvent<RCV_HTTP_STATUS_200>() {

	switch(state()) {
	case AUTHETICATION:
		return AUTHETICATION_PASS;
	case SIGNING:
		return AUTHETICATION_PASS;
	case SEALING:
		return AUTHETICATION_PASS;
	default:
		return AUTHETICATION_FAIL;
	}
}

template<> State Ntlm_Fsm::processEvent<RCV_HTTP_STATUS_407>() {

	switch(state()) {
	case AUTHETICATION:
		actionTarget()->sendInitMessage();
		return SIGNING;
	case SIGNING:
		actionTarget()->parseRcvChallengeMessage();
		actionTarget()->sendFinalMessage();
		return SEALING;
	case SEALING:
		return AUTHETICATION_FAIL;
	default:
		return AUTHETICATION_FAIL;
	}
}

void Ntlm_Fsm::doHandleEvent(Event event) {
	switch (event) {
	case RCV_HTTP_STATUS_200:
					setState(processEvent<RCV_HTTP_STATUS_200>());
					break;
	case RCV_HTTP_STATUS_407:
					setState(processEvent<RCV_HTTP_STATUS_407>());
					break;
	default:
					break;
	}
}

NtlmAction::NtlmAction(const c4proto::ConnectionParams &params)
	: m_params(params)
{

	std::vector<std::string> elems;

	boost::split(elems,
							 m_params.proxyParams.proxyLogin, boost::is_any_of("\\"));

	if(elems.size() == 2) {
			domain =elems[0];
			login =elems[1];
	} else
	if(elems.size() == 1) {
			login =elems[0];
	} else {
			onError();
			return;
	}

	std::transform(domain.begin(), domain.end(),domain.begin(), ::toupper);
	c4proto::logger()->info("NtlmAction use domain: {} login: {}",domain, login);

	char tmp_hostname[1024] = { 0 };
	gethostname(tmp_hostname, sizeof(tmp_hostname));
	hostname = std::string(tmp_hostname);

}

NtlmAction::~NtlmAction()
{}

void NtlmAction::tranformToUTF16(std::string & str) {
		std::string en_utf16le;
		convertUtf8ToUtf16Le(std::vector<char>(str.begin(), str.end()),	&en_utf16le);
		str = en_utf16le;
}

void NtlmAction::AssignRecvData(std::shared_ptr<httpxx_response> response) {
		store_response = response;
}

std::string NtlmAction::GenerateHttpRequest(std::string ntlm_base64_struct) {
	std::stringstream ss;
	ss << "CONNECT " << m_params.serverIp << ":" << m_params.serverPort << " HTTP/1.1\r\n"
		 << "Host: " << m_params.serverIp << ":" << m_params.serverPort<< "\r\n"
		 << "Proxy-Connection: keep-alive " << "\r\n"
		 << "Proxy-Authorization: NTLM "
		 << ntlm_base64_struct << "\r\n"
		 << "\r\n";
	return ss.str();
}

void NtlmAction::AnswToProxy(const std::string & http_text)
{
				int bw = this->onSendText(http_text);
				if(bw < 0 ) {
//						 sc_log::err("NtlmAction::AnswToProxy bw ", bw);
						 onError();
				}
}

void NtlmAction::sendInitMessage() {
	//Log::inf("Send %s", __FUNCTION__);
				C4_NTLM_AUTH::type_1_message_t type_1_message;
	memset((void*)&type_1_message, 0, sizeof(type_1_message));
	std::string buff, buff_encode;

	strcpy((char*)&type_1_message.protocol, "NTLMSSP");
	type_1_message.type =	 C4_NTLM_AUTH::NTLMSSP_NEGOTIATE;
	type_1_message.flags =	C4_NTLM_AUTH::NegotiateUnicode |		 //0x88207;
													C4_NTLM_AUTH::NegotiateOEM |
													C4_NTLM_AUTH::NegotiateNTLM |
													C4_NTLM_AUTH::RequestTarget |
													C4_NTLM_AUTH::NegotiateNTLM2Key |
													C4_NTLM_AUTH::NegotiateAlwaysSign;
//	sc_log::dbg("flags: ", type_1_message.flags);
	buff.append((char*)&type_1_message, sizeof(type_1_message));


	buff_encode = base64_encode((uint8_t*)buff.data(), buff.size());

	std::string write_str = GenerateHttpRequest(buff_encode);
	AnswToProxy(write_str);
}

void NtlmAction::sendFinalMessage() {
	std::string buff, buff_encode;
	C4_NTLM_AUTH::type_3_message_t type_3_message;
	memset((void*)&type_3_message, 0, sizeof(type_3_message));
	strcpy((char*)&type_3_message.protocol, "NTLMSSP");
	tranformToUTF16(domain);
		tranformToUTF16(login);
	tranformToUTF16(hostname);

	type_3_message.type =	C4_NTLM_AUTH::NTLMSSP_AUTH;
	type_3_message.flags =	C4_NTLM_AUTH::NegotiateUnicode |		 ////0x88205;;
													C4_NTLM_AUTH::NegotiateNTLM |
													C4_NTLM_AUTH::RequestTarget |
													C4_NTLM_AUTH::NegotiateNTLM2Key |
													C4_NTLM_AUTH::NegotiateAlwaysSign;
	//sc_log::dbg("flags: ", type_3_message.flags);

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

	getNTLM2SessionResponse( m_params.proxyParams.proxyPassword,
													 (uint8_t*)nonce.c_str(), nonce.size(), lm_resp, nt_resp);

	buff.append(lm_resp);
	buff.append(nt_resp);
	type_3_message.msg_len = buff.size();

	buff_encode = base64_encode((uint8_t*)buff.data(), buff.size());
	std::string write_str = GenerateHttpRequest(buff_encode);
	AnswToProxy(write_str);
}

void NtlmAction::parseRcvChallengeMessage() {
	std::string buff_decode, ntlm_data;

	std::vector<std::string> elems;
	std::string ntlmString	= store_response->getValueByName<std::string>("Proxy-Authenticate");

	boost::split(elems,
	ntlmString,
	boost::is_any_of(" "));

	if(elems.size() == 2 && elems[0] == "NTLM") {
		buff_decode = base64_decode(elems[1]);

		if(buff_decode.size() >= sizeof(C4_NTLM_AUTH::type_2_message_t)) {
			C4_NTLM_AUTH::type_2_message_t * type_2_message = (C4_NTLM_AUTH::type_2_message_t *)buff_decode.data();

			if(type_2_message->type != C4_NTLM_AUTH::NTLMSSP_CHALLENGE) {
					onError();
					return;
			}

			nonce = std::string((char*)type_2_message->nonce, sizeof(type_2_message->nonce));
	//									sc_log::dbg("Magic: ", (char*)type_2_message->protocol);
	//									sc_log::buf("nonce: ", nonce.data(), nonce.size());
		}
		else {
				onError();
				return;
		}

	} else {
		c4proto::logger()->error("NtlmAction Proxy-Authenticate error format {} ",ntlmString);
		onError();
	}
}
}; // namespase C4_NTLM_AUTH
