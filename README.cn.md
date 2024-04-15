语言: 简体中文 | [English](README.md)

# 铜锁迷你版

铜锁迷你版（tongsuo-mini），中文名称“迷你锁”，是一个轻量级的密码学算法库，专为嵌入式系统和物联网设备等资源受限场景提供常用的密码学算法和安全传输协议，并可以适应超低内存和存储的极限要求。“迷你锁”通过高度模块化，允许用户在编译时只开启需要的功能，不浪费存储空间。
同时，通过紧凑的内存对齐等方式，压缩运行时内存。

## 特性

迷你锁（tongsuo-mini）提供如下特性：

* 高度可定制的模块化编译
* 轻量级密码学算法
  * ASCON AEAD
  * ASCON HASH
* 轻量级安全通信协议
  * OSCORE
  * EDHOC\*
* 基于可预测逻辑的动态二进制加载能力\*
* 传统密码学算法
  * 商用密码算法：SM2\*，SM3，SM4
  * 国际密码学算法\*：AES，SHA系列，RSA，ECDSA，EdDSA
* 传统安全通信协议
  * TLS协议\*
  * TLCP协议\*

注：\*号表示待开发

## 构建

构建依赖cmake，make和C编译器（gcc或者clang），基于源代码构建迷你锁如下：

```bash
# 下载源代码
git clone https://github.com/Tongsuo-Project/tongsuo-mini
cd tongsuo-mini

mkdir build
cd build

# 编译所有模块使用-DWITH_ALL=ON, 编译指定模块-DWITH_<module>=ON，例如-DWITH_ASCON=ON
# 查看所有可用的编译选项, cmake -LH ..
cmake -DWITH_ALL=ON ..
make -j

# 安装
make install
```

## 测试

测试使用Python3，在test目录下创建虚拟环境并安装依赖：

```bash
cd test
python3 -m venv .venv
source .venv/bin/activate
pip3 install -r requirements.txt
```

然后在build目录下执行：
```bash
ctest
```
或者在test目录下执行：
```bash
pytest .
```
