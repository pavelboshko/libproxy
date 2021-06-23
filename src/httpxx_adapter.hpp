#pragma once
#include <httpxx/http.hpp>
#include <boost/algorithm/string.hpp>
#include <vector>
#include <type_traits>

struct httpxx_response {
public:
	enum status{complete, header_complete, not_complete, bad};
	std::string url;
	std::string host;
	std::string port;
	std::string method;
	std::string authorization;
	std::string proxy_authorization;
	std::string server_name;

	httpxx_response() : response_(request_body_), status_(not_complete) { ; }

	status feed(const std::string & data) {

		int used = 0;
		try {
			if(status_ == complete) {
				return complete;
			}

			store_req_.append(data);

			while (used < data.size()) {
				used += response_.feed(data.data() + used, data.size() - used);
			}


			if( response_.headers_complete()){
				status_ = header_complete;
				if( response_.complete()){
					status_ = complete;
				}
			}


			return status_;
		}	catch (http::Error & e) {
			return bad;
		}
		catch (std::exception & e) {
			return bad;
		}
	}

	void clear() {
		store_req_.clear();
		response_.clear();
		request_body_.clear();
		url.clear();
		host.clear();
		port.clear();
		method.clear();
		authorization.clear();
		proxy_authorization.clear();
		server_name.clear();
		status_ = not_complete ;
	}

	const std::string & getRaw() { return store_req_; }
	const std::string & getHeader() { return request_header_; }
	const std::string & getBody() { return request_body_; }
	httpxx_response::status getStatus() { return status_; }
	bool bodyReady() const { return response_.complete(); }
	bool headerReady() const { return response_.headers_complete(); }
	int getHttpStatus() const { return response_.status(); }


	template <class T>
	typename std::enable_if<std::is_same< T, std::string >::value, T>::type
	getValueByName(const std::string & name) {
		return response_.header(name);
	}

	template <class T>
	typename std::enable_if<std::is_same< T, int >::value, T>::type
	getValueByName(const std::string & name) {
		return -1;
	}




private:
	std::string store_req_;
	std::string request_body_;
	std::string request_header_;
	http::UserBufferedResponse<std::string> response_;
	status	status_;

};
