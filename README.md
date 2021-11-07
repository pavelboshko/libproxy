# libproxy 
lightweight http proxy library, for authentication on proxy server via protocols:
- Basic
- NTLMv2

Library provide auto detect  protocol of authentication.

# startup
######  load all modules
git submodule update --init --recursive

######  build lib only
cd build/linux/
mkdir build
cd build
cmake ..
make

######  build cli test
cd test/ 
mkdir build
cd build
cmake ..
make


