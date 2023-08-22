# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://github.com/Tongsuo-Project/tongsuo-mini/blob/main/LICENSE

import tf
import pytest


@pytest.mark.parametrize(
    "scheme, kat_file",
    [
        ("hash", "test_ascon_data/ascon_hash.txt"),
        ("hasha", "test_ascon_data/ascon_hasha.txt"),
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

            if "Count" in tb and "Msg" in tb and "MD" in tb:
                with subtests.test(i=tb["Count"]):
                    tf.ok(
                        "test_ascon_hash -scheme {} -msg {} -md {}".format(
                            scheme, tb["Msg"], tb["MD"]
                        )
                    )
                    tb.clear()
