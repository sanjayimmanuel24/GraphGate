# Copyright The IETF Trust 2018, All Rights Reserved
# -*- coding: utf-8 -*-
from __future__ import unicode_literals, print_function, division

import base64
import re
import sys
import textwrap

from collections import OrderedDict
from lxml.etree import _Comment, _ProcessingInstruction

from urllib.request import quote

import xml2rfc.log


def find_duplicate_ids(schema, tree):
    # get attributes specified with data type "ID"
    id_data = schema.xpath("/x:grammar/x:define/x:element//x:attribute/x:data[@type='ID']", namespaces=namespaces)
    attr = set([ i.getparent().get('name') for i in id_data ])
    # Check them one by one
    return find_duplicate_attr_values(attr, tree)


def slugify(s):
    s = s.strip().lower()
    s = re.sub(r'[^\w\s/|@=-]', '', s)
    s = re.sub(r'[-_\s/|@=]+', '_', s)
    s = s.strip('_')
    return s
