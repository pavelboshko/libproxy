#pragma once

#include <sstream>
#include <iostream>
#include <algorithm>
#include <map>
#include <vector>
#include <functional>
#include <memory>

#include "../../log.hpp"
#include "ntlm_types.h"
#include "abstract_fsm.h"
#include "proxy_auth.h"
#include "httpxx_adapter.hpp"

namespace C4_NTLM_AUTH {

class Actions {
public:
	virtual void sendInitMessage() = 0;
	virtual void parseRcvChallengeMessage() = 0;
	virtual void sendFinalMessage() = 0;
	virtual void AssignRecvData(std::shared_ptr<httpxx_response> response) = 0;

	virtual ~Actions()
	{}

	std::function<int(const std::string &)> onSendText;
	std::function<int(const std::vector<char> &)> onSendBinary;
	std::function<void()> onError;
protected:
	std::shared_ptr<httpxx_response> store_response;
};

enum Event {
	RCV_HTTP_STATUS_200,
	RCV_HTTP_STATUS_401,
	RCV_HTTP_STATUS_407,
};

enum State {
	AUTHETICATION,
	SIGNING,
	SEALING,
	AUTHETICATION_PASS,
	AUTHETICATION_FAIL
};

class Ntlm_Fsm : public AbstractFsm<Event, State, Actions> { // TODO наследоватся от Observer
public:
	Ntlm_Fsm(Actions* const actions): AbstractFsm<Event, State, Actions>(actions, AUTHETICATION)
	{}

	template<Event e> State processEvent();

	virtual void onLeftState(State state)
	{}

	virtual void doHandleEvent(Event event);

	void feedResponse(std::shared_ptr<httpxx_response> response ) {

		assert(response != nullptr);

		switch ( response->getHttpStatus()) {
		case 200:
				doHandleEvent(RCV_HTTP_STATUS_200);
				break;
		case 401:
				actionTarget()->AssignRecvData(response);
				doHandleEvent(RCV_HTTP_STATUS_401);
				break;
		case 407:
				actionTarget()->AssignRecvData(response);
				doHandleEvent(RCV_HTTP_STATUS_407);
				break;
		default:
				setState(AUTHETICATION_FAIL);
				break;
		}
	}

	bool NtlmAutheticationComlete() const {
			return (state() == AUTHETICATION_FAIL || state() == AUTHETICATION_PASS);
	}

	void startAuth() {
			doHandleEvent(C4_NTLM_AUTH::RCV_HTTP_STATUS_407);
	}
};

class NtlmAction : public C4_NTLM_AUTH::Actions {
public:
	NtlmAction(const c4proto::ConnectionParams &params);
	void tranformToUTF16(std::string & str);
	~NtlmAction();
	virtual void sendInitMessage();
	virtual void parseRcvChallengeMessage() ;
	virtual void sendFinalMessage() ;
	virtual void AssignRecvData(std::shared_ptr<httpxx_response> response);

protected:
	std::string login, domain, passw, hostname, nonce;
	std::string lm_resp, nt_resp;
	const c4proto::ConnectionParams & m_params;

	std::string GenerateHttpRequest(std::string ntlm_base64_struct);
	void AnswToProxy(const std::string & http_text);
};

} // namespase
