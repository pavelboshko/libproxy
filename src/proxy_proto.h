#pragma once
#include <memory>
#include "common_types.h"

namespace libproxy {

class IProxyProto;
typedef  std::shared_ptr<IProxyProto> PProxyProto;
class IProxyProto
{
public:
	virtual void start() = 0;
	virtual void insert(const char *s, size_t length) = 0;
	static PProxyProto createBasic();
	static PProxyProto createNTLM();
};




}
