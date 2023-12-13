# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://github.com/Tongsuo-Project/tongsuo-mini/blob/main/LICENSE

import tf
import pytest


@pytest.mark.parametrize(
    "algo, kat_file",
    [
        ("ascon-hmac", "test_hmac_data/ascon_hmac.txt"),
        ("ascon-hmaca", "test_hmac_data/ascon_hmaca.txt"),
    ],
)
def test_ascon_hmac(algo, kat_file, subtests):
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

            if "Count" in tb and "Msg" in tb and "Key" in tb and "Tag" in tb:
                with subtests.test(i=tb["Count"]):
                    tf.ok(
                        "test_ascon_hmac -algo {} -key {} -msg {} -tag {}".format(
                            algo, tb["Key"], tb["Msg"], tb["Tag"]
                        )
                    )
                tb.clear()
