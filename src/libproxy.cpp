#include "libproxy.h"
#include "callbacks_mediator.h"
#include <sstream>
#include "log.h"

using namespace libproxy;


proxyAuthHelper::proxyAuthHelper(const PCallbacks &c, const connectionParams &cp) :
	_pcallbacks(c),
	_connectionParams(cp),
	_pfsm(std::make_shared<libproxyFsm>(this))
{
	ICallbackMediator::getMediator()->subscribe([this](const std::string & s) {
		_pcallbacks->onSendData(s);
	});

	ICallbackMediator::getMediator()->subscribe([this](userCreds & uc, connectionParams & cp) {
		cp = _connectionParams;
		_pcallbacks->onUserCredsRequire(uc);
	});

	ICallbackMediator::getMediator()->subscribe([this]() {
		_pcallbacks->onRequireData();
	});

	ICallbackMediator::getMediator()->subscribe([this](bool status) {
		if(status) {
			_pfsm->onEvent(Event::Http200);
		} else {
			_pfsm->onEvent(Event::Http5xx);
		}
	});
}

void proxyAuthHelper::start()
{
	if(_pfsm->state() == State::Init) {
		std::stringstream ss;
		ss << "CONNECT "
		<< _connectionParams._remoteHost << ":" << _connectionParams._remotePort
		<< " HTTP/1.0\r\nHOST "
		<< _connectionParams._remoteHost << ":" <<_connectionParams._remotePort
		<< "\r\n\r\n";
		_pcallbacks->onSendData(ss.str());
		_pfsm->onEvent(SentConnect);
		_pcallbacks->onRequireData();
	} else if (_pfsm->state() == State::NeedAuth){
		_auth_pproto->start();
	} else {
		LIBPROXY_TRACE_D("");
	}
}

void proxyAuthHelper::insert(const char *s, size_t length)
{
	if(_pfsm->state() == State::SentConnectSucceed) {
		auto data = reinterpret_cast<const char*>(s);
		std::size_t size = length;
		std::size_t used = 0;
		std::size_t pass = 0;

		while ((used < size) && !_httpxx_response.complete()) {
			used += _httpxx_response.feed(data + used, size-used);
		}

		if(!_httpxx_response.complete()) {
			if(_httpxx_response.status() == 200) {
				_pfsm->onEvent(Event::Http200);
				return;
			}
			_pcallbacks->onRequireData();
		} else {
			Event e = handleHttpHeaderReady();
			_pfsm->onEvent(e);
		}


	} else if (_pfsm->state() == State::NeedAuth){
		libproxyAssert(_auth_pproto != nullptr);
		_auth_pproto->insert(s, length);
	}
	else {
		std::cerr << __FUNCTION__ << " " << __LINE__ << "\n";
		_pfsm->onEvent(Event::Http5xx);
	}

}

Event proxyAuthHelper::handleHttpHeaderReady()
{
//

	auto code = _httpxx_response.status();
	LIBPROXY_TRACE_D("handle http cade: ", code);
	switch (code) {
		case 200: return Event::Http200;
		case 407: return Event::Http407;
		default:
			switch (code / 100) {
				case 5: return Event::Http5xx;
				default: return Event::OtherHttp;
			}
		break;

	}
}

void proxyAuthHelper::onStateChange(State old, State current)
{
	LIBPROXY_TRACE_D( StateToStr(old), " -> ", StateToStr(current));
	switch (current) {
		case State::NeedAuth:
			_auth_pproto = createAuthProto();
			if(needReconnect()) {
				_pcallbacks->onReconnectRequire();
			}
			break;
		case State::Fail:
			_pcallbacks->onError();
			break;
		case State::AuthSucceed:
			_pcallbacks->onProxyLoginSucceed();
			break;
		default:
			break;

	}
}

PProxyProto proxyAuthHelper::createAuthProto()
{
	auto proxy_auth_proto = _httpxx_response.header("Proxy-Authenticate");
	LIBPROXY_TRACE_D("proxy_auth_proto", proxy_auth_proto, "need session close", _httpxx_response.header("Connection"));
	if(proxy_auth_proto.find("Basic") != std::string::npos) {
		return IProxyProto::createBasic();
	} else if(proxy_auth_proto.find("NTLM") != std::string::npos) {
		return IProxyProto::createNTLM();
	} else {
		return nullptr;
	}
}

bool proxyAuthHelper::needReconnect()
{
	 auto c = _httpxx_response.header("Connection");
	 if(c == "close") return true;
	 return false;
}
