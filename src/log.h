#pragma once
#include <string.h>
#include <stdarg.h>
#include <sstream>
#include <iostream>

#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

static inline void logwriter(const std::string & s) {
	std::cout << s;
}


template <typename ...Args>
static inline void tracefn(int line, const char* fileName, const char* typemsg, Args&& ...args)
{
	std::ostringstream stream;
	stream << typemsg << " " << fileName << "(" << line << ") : ";
	(stream << ... << std::forward<Args>(args)) << std::endl;

	logwriter(stream.str());
}


#define LIBPROXY_TRACE_D(...) tracefn(__LINE__, __FILENAME__, "D",  __VA_ARGS__)
#define LIBPROXY_TRACE_E(...) tracefn(__LINE__, __FILENAME__, "E",  __VA_ARGS__)
