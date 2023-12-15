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
pip3 install -r test/requirements.txt
```

Then run the command in the build directory:

```bash
ctest
```

Or run the command in the test directory:

```bash
pytest .
```
