#include "proxy_auth.h"
#include "ntlm_fsm.h"
#include <httpxx/http.hpp>
#include "legacy/crypto_utils.hpp"

#include <sstream>
#include <string>

#include "httpxx_adapter.hpp"
#include "sc_log.h"
#include "../../log.hpp"

namespace c4proto {
namespace connection {
namespace proxy {

class authProccessor {
public:
	authProccessor(const proxyAuthenticator * authenticator) :
		m_authenticator(authenticator),
		m_response(std::make_shared<httpxx_response>())
	{
		m_connect_buf << "CONNECT "
					  << m_authenticator->m_conParams.serverIp << ":" << m_authenticator->m_conParams.serverPort
					  << " HTTP/1.0\r\nHOST "
					  << m_authenticator->m_conParams.serverIp << ":" << m_authenticator->m_conParams.serverPort;
	}

	void sendConnect(boost::system::error_code & err) {
		int bw = m_authenticator->onSendText(m_connect_buf.str());
		if(bw < 0) {
			boost::system::error_code	proxy_err(c4proto::Errors::InternalFatalError,
												  c4proto::connection::proxy::category);
			m_authenticator->onAuthenticationComplete(proxy_err);
			return;
		}
	}

	void storeAnsw(const char *	data, size_t len) {
		httpxx_response::status response_status;

		response_status = m_response->feed(std::string(data, len));
		c4proto::logger()->debug("Proxy storeAnsw headerReady {} bodyReady {} return\n{}",
							   m_response->headerReady(),
							   m_response->bodyReady(),
							   m_response->getRaw());


		if(response_status == httpxx_response::bad) {
			c4proto::logger()->error("Proxy no_auth | basic , bad answear");
			boost::system::error_code inernal_error = boost::system::error_code(c4proto::Errors::InternalFatalError,
																				c4proto::connection::proxy::category);
			m_authenticator->onAuthenticationComplete(inernal_error);
			return;
		}


		if(m_response->headerReady()) {
			c4proto::logger()->info("storeAnsw NoAuth - Basic	proxy return http status {}",m_response->getHttpStatus());
			if(m_response->getHttpStatus() == 200) {
				boost::system::error_code no_error;
				m_authenticator->onAuthenticationComplete(no_error);
				return;
			}

			boost::system::error_code no_error;
			switch (m_response->getHttpStatus()) {
			case 200:
				m_authenticator->onAuthenticationComplete(no_error);
				break;
			default:
				boost::system::error_code login_fail_error = boost::system::error_code(c4proto::Errors::LoginFailOnProxy,
																					   c4proto::connection::proxy::category);
				m_authenticator->onAuthenticationComplete(login_fail_error);
				break;
			}
		} else {
			m_authenticator->onNeedMoreData();
		}
	}


protected:
	const proxyAuthenticator * m_authenticator;
	std::stringstream m_connect_buf;
	std::shared_ptr<httpxx_response> m_response;
};

class noAuth : public ProxyImplBase, public authProccessor {
public:
	noAuth(const proxyAuthenticator * auth) : authProccessor(auth)
	{
		c4proto::logger()->debug("noAuth proxy create");
		m_connect_buf << "\r\n\r\n";
	}

	virtual void startAuthentication(boost::system::error_code & err)	{
		sendConnect(err);
	}

	virtual void feedData(const char *	data, size_t len) {
		storeAnsw(data, len);
	}

	virtual ~noAuth() { ; }
};

class basicAuth : public ProxyImplBase , public authProccessor {
public:
	basicAuth(const proxyAuthenticator * auth)	:	authProccessor(auth)
	{
		c4proto::logger()->debug("basicAuth proxy create");

		m_connect_buf << "\r\n";
		std::string login_passwd(auth->m_conParams.proxyParams.proxyLogin);
		login_passwd += ":";
		login_passwd += auth->m_conParams.proxyParams.proxyPassword;
		m_connect_buf << "Proxy-Authorization: Basic " << base64_encode(( const uint8_t *)login_passwd.data(), login_passwd.size()) << "\r\n";
		m_connect_buf << "\r\n";
	}

	virtual void startAuthentication(boost::system::error_code & err)	{ // TODO combine	with noAuth
		sendConnect(err);
	}

	virtual void feedData(const char *	data, size_t len) {
		storeAnsw(data, len);
	}

	virtual ~basicAuth() { ; }
};

class ntlmAuth : public ProxyImplBase {
public:
	ntlmAuth(const proxyAuthenticator * auth) :
		m_authenticator(auth),
		action(m_authenticator->m_conParams),
		fsm(&action)
	{
		c4proto::logger()->debug("ntlmAuth proxy create");
		action.onSendText	= [this](const std::string & data) -> int {
			return m_authenticator->onSendText(data);
		};

		action.onError	= [&]() {
			c4proto::logger()->error("ntlmAuth startAuthentication error");

			boost::system::error_code	err(c4proto::Errors::InternalFatalError,
											c4proto::connection::proxy::category);

			m_authenticator->onAuthenticationComplete(err);
		};
		m_response.reset(new httpxx_response());
	}

	virtual void startAuthentication(boost::system::error_code & err)	{
		fsm.startAuth();
	}

	virtual void feedData(const char *	data, size_t len) {

		m_response->feed(std::string(data, len));
		c4proto::logger()->debug("Proxy storeAnsw headerReady {} bodyReady {}",
							   m_response->headerReady(),
							   m_response->bodyReady());

		if(response_status == httpxx_response::bad) {
			boost::system::error_code inernal_error = boost::system::error_code(c4proto::Errors::InternalFatalError,
																				c4proto::connection::proxy::category);
			m_authenticator->onAuthenticationComplete(inernal_error);
			return;
		}

		if(!m_response->headerReady()) {
			m_authenticator->onNeedMoreData();
			return;

		} else {
			c4proto::logger()->info("feedData ntlmAuth	proxy return http status {}",m_response->getHttpStatus());
			if(m_response->getHttpStatus() == 200) {
				boost::system::error_code no_error;
				m_authenticator->onAuthenticationComplete(no_error);
				return;
			}

			if(!m_response->bodyReady()) {
				m_authenticator->onNeedMoreData();
				return;
			}

			fsm.feedResponse(m_response);
			m_response.reset(new httpxx_response());
			c4proto::logger()->debug("Proxy storeAnsw NtlmAutheticationComlete {}",fsm.NtlmAutheticationComlete());

			if(!fsm.NtlmAutheticationComlete()) {
				m_authenticator->onNeedMoreData();
			}
			else {
				boost::system::error_code error;
				switch (fsm.state()) {
				case C4_NTLM_AUTH::State::AUTHETICATION_PASS:
					m_authenticator->onAuthenticationComplete(error);
					break;
				default:
					error = boost::system::error_code(c4proto::Errors::LoginFailOnProxy,
													  c4proto::connection::proxy::category);
					m_authenticator->onAuthenticationComplete(error);
					break;
				}

			}

		}
	}

	const proxyAuthenticator * m_authenticator;
	std::shared_ptr<httpxx_response> m_response;
	httpxx_response::status response_status = httpxx_response::not_complete;
	C4_NTLM_AUTH::NtlmAction action;
	C4_NTLM_AUTH::Ntlm_Fsm fsm;

	virtual ~ntlmAuth() { ; }

};

proxyAuthenticator::proxyAuthenticator(const c4proto::ConnectionParams & connectionParams) :
	m_conParams(connectionParams)

{
	switch (connectionParams.proxyParams.authType) {
	case c4proto::NoAuth:
		impl.reset(new noAuth(this));
		break;
	case c4proto::BasicAuth:
		impl.reset(new basicAuth(this));
		break;
	case c4proto::NTLMAuth:
		impl.reset(new ntlmAuth(this));
		break;
	default:
		assert(false);
		break;
	}
};

void proxyAuthenticator::startAuthentication(boost::system::error_code & err) {
	impl->startAuthentication(err);
}

void proxyAuthenticator::feedData(const char *	data, size_t len) {
	impl->feedData(data, len);
}

}
}
}	// namespace c4proto

