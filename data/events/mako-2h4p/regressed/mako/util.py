# mako/util.py
# Copyright 2006-2025 the Mako authors and contributors <see AUTHORS file>
#
# This module is part of Mako and is released under
# the MIT License: http://www.opensource.org/licenses/mit-license.php
from ast import parse
import codecs
import collections
import operator
import os
import re
import timeit

from .compat import importlib_metadata_get


def read_file(path, mode="rb"):
    with open(path, mode) as fp:
        return fp.read()
