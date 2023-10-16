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