语言: 简体中文 | [English](README.md)

# 铜锁迷你版

铜锁迷你版（tongsuo-mini），中文名称“迷你锁”，是一个轻量级的密码学算法库，专为嵌入式系统和物联网设备等资源受限场景提供常用的密码学算法和安全传输协议，并可以适应超低内存和存储的极限要求。“迷你锁”通过高度模块化，允许用户在编译时只开启需要的功能，不浪费存储空间。
同时，通过紧凑的内存对齐等方式，压缩运行时内存。

## 构建依赖

迷你锁依赖于cmake进行构建，以及python工具链进行自动化测试，具体来说，有：

* cmake
* python
  * pytest

上述工具在不同操作系统的安装方式也有所不同，请参考对应操作系统的安装说明。以下是在macOS上安装上述构建依赖的一个典型例子（基于homebrew）：

~~~
brew install cmake
brew install python
sudo pip3 install -r test/requirements.txt
~~~

## 构建

构建使用cmake，下载源代码后进入源代码根目录执行：

```bash
mkdir build
cd build
cmake ..
make
make test
```

## 特性

迷你锁（tongsuo-mini）提供如下特性：

* 高度可定制的模块化编译
* 轻量级密码学算法
   * ASCON AEAD
   * ASCON HASH
* 轻量级安全通信协议
   * OSCORE
   * EDHOC
* 基于可预测逻辑的动态二进制加载能力
* 传统密码学算法
  * 商用密码算法：SM2，SM3，SM4
  * 国际密码学算法：AES，SHA系列，RSA，ECDSA，EdDSA
* 传统安全通信协议
  * TLS协议
  * TLCP协议