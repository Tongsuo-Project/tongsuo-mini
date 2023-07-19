# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://github.com/Tongsuo-Project/tongsuo-mini/blob/main/LICENSE

import tf
import binascii


def test_sm4_api():
    tf.ok("test_sm4_api")


def test_minisuo_sm4_cbc(setup_temp2):
    infile, outfile = setup_temp2
    key = "0123456789ABCDEFFEDCBA9876543210"
    iv = "0123456789ABCDEFFEDCBA9876543210"
    plaintext = "0123456789ABCDEFFEDCBA98765432100123456789ABCDEFFEDCBA9876543210"
    ciphertext = "2677F46B09C122CC975533105BD4A22AF6125F7275CE552C3A2BBCF533DE8A3B"

    tf.writef(infile, binascii.unhexlify(plaintext))

    tf.ok(
        "minisuo sm4 -enc -mode cbc -key {key} -iv {iv} -in {infile} -out {outfile} -nopad".format(
            key=key, iv=iv, infile=infile, outfile=outfile
        )
    )

    res = tf.readf(outfile)
    assert res == binascii.unhexlify(ciphertext)
