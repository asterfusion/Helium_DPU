#!/usr/bin/env python
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2019 Intel Corporation

from __future__ import print_function
import sys
from os.path import dirname, basename, join, exists


def is_function_line(ln):
    return ln.startswith('\t') and ln.endswith(';\n') and ":" not in ln


def main(args):
    if not args[1].endswith('version.map') or \
            not args[2].endswith('exports.def'):
        return 1

# special case, allow override if an def file already exists alongside map file
    override_file = join(dirname(args[1]), basename(args[2]))
    if exists(override_file):
        with open(override_file) as f_in:
            functions = f_in.readlines()

# generate def file from map file.
# This works taking indented lines only which end with a ";" and which don't
# have a colon in them, i.e. the lines defining functions only.
    else:
        with open(args[1]) as f_in:
            functions = [ln[:-2] + '\n' for ln in sorted(f_in.readlines())
                         if is_function_line(ln)]
            functions = ["EXPORTS\n"] + functions

    with open(args[2], 'w') as f_out:
        f_out.writelines(functions)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
