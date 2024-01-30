# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://github.com/Tongsuo-Project/tongsuo-mini/blob/main/LICENSE

import tf
import pytest


@pytest.mark.parametrize(
    "scheme, kat_file",
    [
        ("ascon128", "test_ascon_data/ascon_aead128.txt"),
        ("ascon128a", "test_ascon_data/ascon_aead128a.txt"),
    ],
)
def test_ascon_aead(scheme, kat_file, subtests):
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

            if (
                "Count" in tb
                and "Key" in tb
                and "Nonce" in tb
                and "AD" in tb
                and "PT" in tb
                and "CT" in tb
            ):
                with subtests.test(i=tb["Count"]):
                    tf.ok(
                        "test_ascon_aead -scheme {} -key {} -nonce {} -ad {} -pt {} -ct {}".format(
                            scheme, tb["Key"], tb["Nonce"], tb["AD"], tb["PT"], tb["CT"]
                        )
                    )
                    tb.clear()
