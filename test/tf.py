# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://github.com/Tongsuo-Project/tongsuo-mini/blob/main/LICENSE

import os
import sys
import subprocess

current_dir = os.path.split(os.path.realpath(__file__))[0]

def ok(cmd, input=None):
    """
    input should be bytes or None
    """
    print("$ " + cmd)

    child = subprocess.Popen(cmd, stdout=subprocess.PIPE, stdin=subprocess.PIPE, shell=True,
                             env=dict(PATH=os.path.join(os.path.dirname(current_dir), 'build')))

    if input is not None:
        print(">")
        sys.stdout.buffer.write(input)

        output = child.communicate(input)[0]
    else:
        output = child.communicate()[0]

    child.stdin.close()

    assert child.returncode == 0

    print(output.decode("utf-8"))
    return output
