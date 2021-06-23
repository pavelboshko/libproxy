#pragma once
#include <string>
#include <exception>
#include <iostream>
#include <memory>

namespace libproxy {

enum Event {
	SentConnect, Http407, Http200, Http5xx, OtherHttp
};

enum State {
	Init, SentConnectSucceed, Fail, AuthSucceed, NeedAuth
};
std::string EventToStr(Event e) {
	switch (e) {
		case SentConnect: return "SentConnect";
		case Http407: return "Http407";
		case Http200: return "Http200";
		case Http5xx: return "Http5xx";
		case OtherHttp: return "OtherHttp";
		default:
			throw std::runtime_error("");
			break;
	}
}
std::string StateToStr(State s) {
	switch (s) {
		case Init: return "Init";
		case SentConnectSucceed: return "SentConnectSucceed";
		case Fail: return "Fail";
		case AuthSucceed: return "AuthSucceed";
		case NeedAuth: return "NeedAuth";
		default:
			throw std::runtime_error("");
			break;
	}
}

class ILibproxyFsm
{
public:
	virtual void onStateChange(State old, State current) = 0;
};

class libproxyFsm {
public:
	libproxyFsm(ILibproxyFsm * c) : _state(Init), _calbacks(c) {
	}

	template<typename... Params>
	void onEvent(Event e, Params... args) {
		switch (_state) {
			case Init:
				switch (e) {
					case SentConnect:
						setState(SentConnectSucceed);
						break;
					default:
					break;
				}
				break;
			case SentConnectSucceed:
				switch (e) {
					case Http200:
						setState(AuthSucceed);
						break;
					case Http407:
						setState(NeedAuth);
						break;
					case Http5xx:
						setState(Fail);
						break;
					default:
						break;
				}
				break;
			case Fail:
				break;
			case AuthSucceed:
				break;
			case NeedAuth:
				switch (e) {
					case Http200:
						setState(AuthSucceed);
						break;
					case Http407:
					case Http5xx:
						setState(Fail);
						break;
					default:
						break;
				}
				break;
			default:
				throw std::runtime_error("");
				break;
		}
	}

	void reset() {

	}

	void setState(const State &state)  {
		auto old(_state);
		if(old != state) {
			_state = state;
			_calbacks->onStateChange(old, _state);
		}
	}
	State state() const {
		return _state;
	}

private:
	State _state;
	ILibproxyFsm * _calbacks;

};
typedef std::shared_ptr<libproxyFsm> PLFsm;

}
