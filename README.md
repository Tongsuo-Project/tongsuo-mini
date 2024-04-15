Language: English | [简体中文](README.cn.md)

# Tongsuo-mini

This project, tongsuo-mini (stands for 'mini copper lock' in Chinese, or 'minisuo' for its Chinese pronunciation), is a lightweight cryptography library that provides cryptographic primitives and secure network protocol for embbeded systems and IoT devices.

Tongsuo-mini can be used in constrained environment while requiring small memory and storage usage.

Tongsuo-mini is a member project of the Tongsuo open source community.

## Feature

Tongsuo-mini has the following features:

* Highly configurable modular build system
* Lightweight cryptographic algorithm
  * ASCON AEAD
  * ASCON HASH
* Lightweight secure network protocol
  * OSCORE
  * EDHOC\*
* Dynamic binary loading based on predication logic\*
* Oridnary cryptography algorithm
  * Chinese Shangmi: SM2\*，SM3，SM4
  * others\*: AES, SHA, RSA, ECDSA, EdDSA
* Ordinary secure network protocol
  * TLS\*
  * TLCP\*

Note: \* means the feature is under development

## Build

The build depends on cmake, make and C compiler (gcc or clang).
Build tongsuo-mini from the source code as follows:

```bash
# Download source code
git clone https://github.com/Tongsuo-Project/tongsuo-mini
cd tongsuo-mini

mkdir build
cd build

# Compile all modules with -DWITH_ALL=ON, compile specific module with -DWITH_<module>=ON, e.g. -DWITH_ASCON=ON
# View all available compilation options, cmake -LH ..
cmake -DWITH_ALL=ON ..
make -j

# If you need to install
make install
```

## Test

To test with Python3, create a virtual environment in the test directory and install the dependencies:

```bash
cd test
python3 -m venv .venv
source .venv/bin/activate
pip3 install -r requirements.txt
```

Then run the command in the build directory:

```bash
ctest
```

Or run the command in the test directory:

```bash
pytest .
```
