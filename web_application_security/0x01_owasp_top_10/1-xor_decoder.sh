#!/bin/bash
python3 -c "
import base64,sys;
b=base64.b64decode(sys.argv[1]);
print(''.join(chr(c^0x5F) for c in b))" "${1#\{xor\}}"
