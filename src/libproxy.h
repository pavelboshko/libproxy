#pragma once
#include <string>
#include <vector>
#include <memory>
#include "proxy_proto.h"
#include "common_types.h"
#include "libproxy_fsm.h"
#include "proxy_proto.h"
#include <httpxx/http.hpp>

namespace libproxy {

class proxyAuthHelper : public ILibproxyFsm
{
public:
	proxyAuthHelper(const PCallbacks &  p, const connectionParams & cp);
	void start();
	void insert(const char * data, size_t size);
private:
	Event handleHttpHeaderReady();
	void onStateChange(State old, State current) override;
	PProxyProto createAuthProto();
	bool needReconnect();
private:
	const PCallbacks _pcallbacks;
	connectionParams _connectionParams;
	PProxyProto _auth_pproto;
	PLFsm _pfsm;
	http::BufferedResponse _httpxx_response;


};


} // namespace name
