#include "proxy_proto.h"
#include "callbacks_mediator.h"
#include <httpxx/http.hpp>
#include "base64.h"
#include <iostream>
#include <sstream>

using namespace libproxy;

class basicProto : public IProxyProto
{
public:
	basicProto (){
		std::cerr << "create Basic \n";
	}
	void start() override {

		userCreds uc;
		connectionParams cp;
		ICallbackMediator::getMediator()->getCredsParams(uc, cp);

		std::stringstream ss;
		ss << "CONNECT "
		<< cp._remoteHost << ":" << cp._remotePort
		<< " HTTP/1.0\r\nHOST "
		<< cp._remoteHost << ":" <<cp._remotePort
		<< "\r\n";
		std::string login_passwd(uc.login);
		login_passwd += ":";
		login_passwd += uc.password;
		ss << "Proxy-Authorization: Basic " << base64_encode(( const uint8_t *)login_passwd.data(), login_passwd.size()) << "\r\n";
		ss << "\r\n";

		ICallbackMediator::getMediator()->writeToProxySocket(ss.str());
		ICallbackMediator::getMediator()->requireMoreData();
	}

	void insert(const char *s, size_t length) override {
		_httpxx_response.feed(s,length);

		if(_httpxx_response.headers_complete()) {
			ICallbackMediator::getMediator()->sendAuthenticationStatus(_httpxx_response.status() == 200);
		} else {
			ICallbackMediator::getMediator()->requireMoreData();
		}
	}

	http::Response _httpxx_response;
};



PProxyProto IProxyProto::createBasic()
{
	return std::make_shared<basicProto>();
}

