# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://github.com/Tongsuo-Project/tongsuo-mini/blob/main/LICENSE

import os
import tempfile
import pytest


@pytest.fixture
def setup_temp1():
    _, tmp = tempfile.mkstemp(text=True)

    yield tmp

    os.remove(tmp)


@pytest.fixture
def setup_temp2():
    _, tmp1 = tempfile.mkstemp(text=True)
    _, tmp2 = tempfile.mkstemp(text=True)

    yield tmp1, tmp2

    os.remove(tmp1)
    os.remove(tmp2)
