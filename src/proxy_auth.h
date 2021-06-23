#pragma once

#include <memory>
#include <functional>
#include <boost/system/error_code.hpp>
#include "../../types.hpp"

namespace c4proto {
namespace connection {
namespace proxy {

class Category : public boost::system::error_category {
public:
	Category() {
	}

	const char *name() const noexcept {
			const static std::string message ("proxy authentication error category");
			return message.data();
	}

	std::string message(int ev) const {
			return "";
	}

};

extern Category category;

class ProxyImplBase {
public:
	virtual void startAuthentication(boost::system::error_code & err)	=	0;
	virtual void feedData(const char *	data, size_t len) =	0;
};


typedef std::function<int(const std::vector<char> &)> onSendBinary_t;
typedef std::function<int(const std::string &)> onSendText_t;
typedef std::function<void()> onNeedMoreData_t;
typedef std::function<void(boost::system::error_code & err)> onAuthenticationComplete_t;


class proxyAuthenticator{
public:
	proxyAuthenticator(const c4proto::ConnectionParams & connectionParams);
	void startAuthentication(boost::system::error_code & err);
	void feedData(const char *	data, size_t len);

	onSendBinary_t onSendBinary;
	onSendText_t onSendText;
	onNeedMoreData_t onNeedMoreData;
	onAuthenticationComplete_t onAuthenticationComplete;

	const c4proto::ConnectionParams m_conParams;

private:
	std::shared_ptr<ProxyImplBase> impl;
};


}	// namespace proxy
}	// namespace connection
}	// namespace c4proto



