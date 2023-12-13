# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://github.com/Tongsuo-Project/tongsuo-mini/blob/main/LICENSE

import tf
import pytest
import binascii


@pytest.mark.parametrize(
    "kat_file",
    [
        "test_hmac_data/hmac_sm3.txt",
    ],
)
def test_hmac_sm3(kat_file, subtests):
    with open(kat_file) as f:
        tb = {}

        for line in f:
            if line.startswith("#"):
                continue
            line = line.strip()
            if not line:
                continue

            name, value = line.partition("=")[::2]
            tb[name.strip()] = value.strip()

            if "Count" in tb and "Input" in tb and "Key" in tb and "Output" in tb:
                if tb["Input"][0] == '"':
                    tb["Input"] = binascii.hexlify(
                        tb["Input"].strip('"').encode()
                    ).decode()

                if tb["Key"][0] == '"':
                    tb["Key"] = binascii.hexlify(tb["Key"].strip('"').encode()).decode()

                with subtests.test(i=tb["Count"]):
                    tf.ok(
                        "test_hmac_sm3 -key {} -msg {} -tag {}".format(
                            tb["Key"], tb["Input"], tb["Output"]
                        )
                    )

                tb.clear()
