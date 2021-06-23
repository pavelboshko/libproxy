#pragma once
#include <functional>
#include <string>
#include <memory>
#include "common_types.h"

namespace libproxy {

typedef std::function<void(const std::string &)> writeToProxySocket_t;
typedef std::function<void(userCreds &, connectionParams & cp)> getCredsParams_t;
typedef std::function<void()> requireMoreData_t;
typedef std::function<void(bool status)> authenticationStatus_t;


class ICallbackMediator;
typedef std::shared_ptr<ICallbackMediator> PCallbackMediator;

class ICallbackMediator
{
public:
	virtual void subscribe(writeToProxySocket_t fn) = 0;
	virtual void subscribe(getCredsParams_t fn) = 0;
	virtual void subscribe(requireMoreData_t fn) = 0;
	virtual void subscribe(authenticationStatus_t fn) = 0;
	virtual void writeToProxySocket(const std::string &) = 0;
	virtual void getCredsParams(userCreds & uc, connectionParams & cp) = 0;
	virtual void requireMoreData() = 0;
	virtual void sendAuthenticationStatus(bool status) = 0;


	virtual void unsubscribeAll() = 0;
	static PCallbackMediator getMediator();
};
}


