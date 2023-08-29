Language: English | [简体中文](README.cn.md)

# Tongsuo-mini

This project, tongsuo-mini (stands for 'mini copper lock' in Chinese, or 'minisuo' for its Chinese pronunciation), is a lightweight cryptography library that provides cryptographic primitives and secure network protocol for embbeded systems and IoT devices.

Tongsuo-mini can be used in constrained environment while requiring small memory and storage usage.

Tongsuo-mini is a member project of the Tongsuo open source community.

## Build Dependency

Tongsuo-mini's build system depends on 'cmake' and it utilizes toolchain provided by Python for automated testing.

* cmake
* python
  * pytest

The installation of the dependency is very different in various operating systems. This is a typical example on macOS as follows (based on homebrew):

~~~
brew install cmake
brew install python
sudo pip3 install -r test/requirements.txt
~~~

## Build

Use the 'cmake' to build Tongsuo-mini. Run the following steps after Tongsuo-mini has been cloned into a local directory (inside that dir):

```bash
mkdir build
cd build
cmake ..
make
make test
```

## Feature

Tongsuo-mini has the following features:

* Highly configurable modular build system
* Lightweight cryptographic algorithm
  * ASCON AEAD
  * ASCON HASH
* Lightweight secure network protocol
  * OSCORE
  * EDHOC
*  Dynamic binary loading based on predication logic
* Oridnary cryptography algorithm
  * Chinese Shangmi: SM2，SM3，SM4
  * others: AES, SHA, RSA, ECDSA, EdDSA
* Ordinary secure network protocol 
  * TLS/DTLS
  * TLCP
