# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://github.com/Tongsuo-Project/tongsuo-mini/blob/main/LICENSE

import tf

def test_minisuo_version():
    tf.ok("minisuo -v")
    tf.ok("minisuo --version")
