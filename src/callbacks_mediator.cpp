#include "callbacks_mediator.h"
#include <list>
#include <thread>
#include <mutex>

using namespace libproxy;

class CallbackMediator : public ICallbackMediator
{
public:
	CallbackMediator() {}

	void subscribe(writeToProxySocket_t fn) override {
		_writeToProxySocketSubscibers.push_back(fn);
	}

	void writeToProxySocket(const std::string & s) override {
		for(auto & f : _writeToProxySocketSubscibers) f(s);
	}


	void subscribe(getCredsParams_t fn) override {
		_getCredsParamsSubscibers.push_back(fn);
	}

	void getCredsParams(userCreds & uc, connectionParams &cp) override {
		for(auto & f : _getCredsParamsSubscibers) f(uc, cp);
	}

	void subscribe(requireMoreData_t fn) override {
		_requireMoreData.push_back(fn);
	}

	void subscribe(authenticationStatus_t fn) override {
		_authenticationStatus.push_back(fn);
	}

	void sendAuthenticationStatus(bool status) override {
		for(auto & f : _authenticationStatus) f(status);
	}

	void requireMoreData() override {
		for(auto & f : _requireMoreData) f();
	}

	void unsubscribeAll() override {
		_writeToProxySocketSubscibers.clear();
	}

	std::list<writeToProxySocket_t> _writeToProxySocketSubscibers;
	std::list<getCredsParams_t> _getCredsParamsSubscibers;
	std::list<requireMoreData_t> _requireMoreData;
	std::list<authenticationStatus_t> _authenticationStatus;



};


PCallbackMediator ICallbackMediator::getMediator() {
	static std::once_flag flag;
	static PCallbackMediator g_mediator;
	std::call_once(flag, [&](){
		g_mediator.reset(new CallbackMediator());
	});
	return g_mediator;
}
