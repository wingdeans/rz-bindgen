"""
SPDX-FileCopyrightText: 2022 wingdeans <wingdeans@protonmail.com>
SPDX-License-Identifier: LGPL-3.0-only
"""

import sys
import os

from auditwheel.main import main
from auditwheel.wheeltools import InWheel
from auditwheel.elfutils import elf_read_dt_needed
from auditwheel.policy import _POLICIES

with InWheel(sys.argv[4]) as ctx:  # cibuildwheel repair {wheel} argument
    out_lib = next(f for f in os.listdir() if f.startswith("_rizin"))
    rizin_libs = [l for l in elf_read_dt_needed(out_lib) if l.startswith("librz")]

for p in _POLICIES:
    p["lib_whitelist"] += rizin_libs

sys.exit(main())
