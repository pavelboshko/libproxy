#pragma once
#include <string>
#include <vector>


namespace  libproxy {

struct userCreds {
	std::string login;
	std::string password;
	std::string domain;
};

struct connectionParams {
	explicit connectionParams() {}

	explicit connectionParams(const std::string & remoteHost, const uint64_t remotePort) :
		_remoteHost(remoteHost), _remotePort(remotePort)
	{
	}

	const connectionParams & operator=(const connectionParams & c)  {
		_remoteHost = c._remoteHost;
		_remotePort = c._remotePort;
		return *this;
	}

	std::string _remoteHost;
	uint64_t _remotePort;
};

class Callbacks
{
public:
	virtual bool onSendData(const std::string & data) = 0;
	virtual void onRequireData() = 0;
	virtual void onUserCredsRequire(userCreds & uc) = 0;
	virtual void onReconnectRequire() = 0;
	virtual void onProxyLoginSucceed() = 0;
	virtual void onError() = 0;
};
typedef Callbacks* PCallbacks;

static inline void libproxyAssert(bool r, const char * msg = "") {
	if(!r) {
		throw std::runtime_error(msg);
	}
}

}

