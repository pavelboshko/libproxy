#include "libproxy.h"
#include <thread>
#include <boost/asio.hpp>
#include <iostream>
#include <boost/program_options.hpp>


static bool run=true;
static void signalHadler(int dummy) {
	run = false;
}


struct proxyClientOption
{
	proxyClientOption(const boost::program_options::variables_map & vm) {
		if(vm.count("port")) port = vm["port"].as<std::string>();
		if(vm.count("host")) host = vm["host"].as<std::string>();
		if(vm.count("login")) login = vm["login"].as<std::string>();
		if(vm.count("password")) password = vm["password"].as<std::string>();
		if(vm.count("domain")) domain = vm["domain"].as<std::string>();
		if(vm.count("proxy-host")) proxy_host = vm["proxy-host"].as<std::string>();
		if(vm.count("proxy-port")) proxy_port = vm["proxy-port"].as<std::string>();
	}
	std::string port;
	std::string host;
	std::string login;
	std::string password;
	std::string domain;
	std::string proxy_host;
	std::string proxy_port;
};


class proxyClient : public libproxy::Callbacks
{
public:
	proxyClient(const proxyClientOption & po/*const std ::string & proxyhost, const std ::string & proxyport*/) :
		_po(po),
		_resolver(_executor),
		_socket(_executor),
		_query(_po.proxy_host, _po.proxy_port),
		_cp(_po.host, std::atoi(_po.port.c_str()))
	{

		_pah = std::make_shared<libproxy::proxyAuthHelper>(
					this, _cp);

	}

	void connect() {
		doResolve();
		_tr = std::thread([this]() {
			_executor.run();
		});


	}

	~proxyClient() {
		if(_tr.joinable()) _tr.join();
	}
private:


	void doWrire(const std::string && s) {
		boost::system::error_code error;


		boost::asio::write(_socket, boost::asio::buffer(s), error);
		if (error)
		{
			doClose(error);
			return;
		}


	}

	void doResolve() {
		_resolver.async_resolve(_query ,[this](boost::system::error_code error,
					 boost::asio::ip::tcp::resolver::iterator endpoint_iterator) {
			if (error)
			{
				doClose(error);
				return;
			}

			doConnect(endpoint_iterator);
		});
	}

	void doClose(boost::system::error_code & error) {
		std::cerr << "doClose " << error.message() << "\n";
		_socket.close(error);
	}

	void doReadResponse() {

		_socket.async_read_some(boost::asio::buffer(_read_buffer, _read_buffer.size()),
						  [this](boost::system::error_code error, size_t length) {
			if (error)
			{
				doClose(error);
				return;
			}
			_pah->insert((const char*)_read_buffer.data(), length);
		});

	}

	void doConnect(boost::asio::ip::tcp::resolver::iterator it) {
		boost::asio::async_connect(_socket, it,
					   [this](boost::system::error_code error, boost::asio::ip::tcp::resolver::iterator it) {
			if(error) {
				doClose(error);
				return;
			}
			_pah->start();
		});
	}


	bool onSendData(const std::string &data) override {
		std::cerr << "write to proxy:\n" << data;
		doWrire(std::move(data));
		return false;
	}

	void onRequireData() override {
		doReadResponse();
	}

	void onUserCredsRequire(libproxy::userCreds &uc) override {
		uc.login = _po.login;//"proxyuser";
		uc.password = _po.password;
		uc.domain = _po.domain; //"Aa123456";
	}

	void onReconnectRequire() override {
		std::cerr << __FUNCTION__ << "\n";
		doResolve();
	}

	void onProxyLoginSucceed() override {
		std::cerr << __FUNCTION__ << "\n";
	}

	void onError() override {
		std::cerr << __FUNCTION__ << "\n";
	}

private:
	const proxyClientOption & _po;
	boost::asio::io_service _executor;
	std::thread _tr;
	boost::asio::ip::tcp::resolver _resolver;
	boost::asio::ip::tcp::socket _socket;
	boost::asio::ip::tcp::resolver::query _query;
	libproxy::connectionParams _cp;
	std::shared_ptr<libproxy::proxyAuthHelper> _pah;
	std::array<uint8_t, 1024 * 10> _read_buffer;




};

int main(int argc, char *argv[])
{

	signal(SIGINT, signalHadler);

	boost::program_options::options_description desc;
	boost::program_options::variables_map vm;
	std::string special_if_name;

	desc.add_options()
		("port", boost::program_options::value<std::string>(), "port")
		("host", boost::program_options::value<std::string>(), "host")
		("login", boost::program_options::value<std::string>(), "login")
		("password", boost::program_options::value<std::string>(), "password")
		("domain", boost::program_options::value<std::string>(), "domain")
		("proxy-host", boost::program_options::value<std::string>(), "proxy host")
		("proxy-port", boost::program_options::value<std::string>(), "proxy port");
	boost::program_options::store(boost::program_options::parse_command_line(argc, argv, desc), vm);

	proxyClientOption opt(vm);
	proxyClient pc(opt);
	pc.connect();

	while(run) {
		sleep(1);
	}

	std::cerr << "Stoped\n";

	return 0;
}
