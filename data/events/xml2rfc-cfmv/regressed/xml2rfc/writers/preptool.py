# Copyright The IETF Trust 2017, All Rights Reserved
# -*- coding: utf-8 -*-
from __future__ import unicode_literals, print_function

import copy
import datetime
import os
import re
import sys
import traceback as tb
import unicodedata

from codecs import open
from collections import defaultdict, namedtuple
from contextlib import closing

try:
    from xml2rfc import debug
    debug.debug = True
except ImportError:
    pass

from urllib.parse import urlsplit, urlunsplit, urljoin, urlparse
from urllib.request import urlopen

from lxml import etree

from xml2rfc import strings, log
from xml2rfc.boilerplate_id_guidelines import boilerplate_draft_status_of_memo
from xml2rfc.boilerplate_rfc_7841 import boilerplate_rfc_status_of_memo
from xml2rfc.boilerplate_tlp import boilerplate_tlp
from xml2rfc.scripts import get_scripts
from xml2rfc.uniscripts import is_script
from xml2rfc.util.date import get_expiry_date, format_date, normalize_month
from xml2rfc.util.file import can_access, FileAccessError
from xml2rfc.util.name import full_author_name_expansion
from xml2rfc.util.num import ol_style_formatter
from xml2rfc.util.unicode import (
        unicode_content_tags, unicode_attributes, expand_unicode_element,
        isascii, latinscript_attributes, is_svg)
from xml2rfc.utils import build_dataurl, namespaces, sdict, clean_text
from xml2rfc.writers.base import default_options, BaseV3Writer, RfcWriterError


class PrepToolWriter(BaseV3Writer):
    """ Writes an XML file where the input has been modified according to RFC 7998"""

    def validate(self, when, warn=False):
        return super(PrepToolWriter, self).validate(when='%s running preptool'%when, warn=warn)

    def prep(self):
        self._seen_slugs = set()  # Reset cache before prepping
        self.xinclude()
        # Set up reference mapping for later use.  Done here, and not earlier,
        # to capture any references pulled in by the XInclude we just did.
        self.refname_mapping = self.get_refname_mapping()
        self.remove_dtd()
        tree = self.dispatch(self.selectors)
        log.note(" Completed preptool run")
        return tree

    ## Selector notation: Some selectors below have a handler annotation,
    ## with the selector and the annotation separated by a semicolon (;).
    ## Everything from the semicolon to the end of the string is stripped
    ## before the selector is used as an XPath selector.
    selectors = [
        './/keyword',                       # 2.28.   Keyword
        '.;check_unnumbered_sections()',    # 2.46.2  "numbered" Attribute
                                            # 5.1.1.  XInclude Processing
                                            # 5.1.2.  DTD Removal
        '//processing-instruction();removal()',       # 5.1.3.  Processing Instruction Removal
        '.;validate_before()',              # 5.1.4.  Validity Check
        '/rfc;check_attribute_values()',
        '.;check_attribute_values()',       #
        '.;check_ascii_text()',
        '.;normalize_text_items()',
        './/bcp14;check_key_words()',
        './/*[@anchor]',                    # 5.1.5.  Check "anchor"
        '.;insert_version()',               # 5.2.1.  "version" Insertion
        './front;insert_series_info()',     # 5.2.2.  "seriesInfo" Insertion
        './front;insert_date())',           # 5.2.3.  <date> Insertion
        '.;insert_preptime()',              # 5.2.4.  "prepTime" Insertion
        './/ol[@group]',                    # 5.2.5.  <ol> Group "start" Insertion
        '//*;insert_attribute_defaults()',  # 5.2.6.  Attribute Default Value Insertion
        './/relref;to_xref()',
        './/section',                       # 5.2.7.  Section "toc" attribute
        './/note[@removeInRFC="true"]',     # 5.2.8.  "removeInRFC" Warning Paragraph
        './/section[@removeInRFC="true"]',
        '//*[@*="yes" or @*="no"]',         #         convert old attribute false/true
        './front/date',                     # 5.3.1.  "month" Attribute
        './/*[@ascii]',                     # 5.3.2.  ASCII Attribute Processing
        './front/author',
        './/contact',
        './/*[@title]',                     # 5.3.3.  "title" Conversion
        './/*[@keepWithPrevious="true"]',   # 5.3.4.  "keepWithPrevious" Conversion
        '.;fill_in_expires_date()',         # 5.4.1.  "expiresDate" Insertion
        './front;insert_boilerplate()',     # 5.4.2.  <boilerplate> Insertion
        './front;insert_toc()',
        '.;check_series_and_submission_type()', # 5.4.2.1.  Compare <rfc> "submissionType" and <seriesInfo> "stream"
        './/boilerplate;insert_status_of_memo()',  # 5.4.2.2.  "Status of This Memo" Insertion
        './/boilerplate;insert_copyright_notice()', # 5.4.2.3.  "Copyright Notice" Insertion
        './/boilerplate//section',          # 5.2.7.  Section "toc" attribute
        './/reference;insert_target()',     # 5.4.3.  <reference> "target" Insertion
        './/referencegroup;insert_target()',        # <referencegroup> "target" Insertion
        './/reference;insert_work_in_progress()',
        './/reference;sort_series_info()',  #         <reference> sort <seriesInfo>
        './/name;insert_slugified_name()',  # 5.4.4.  <name> Slugification
        './/references;sort()',             # 5.4.5.  <reference> Sorting
        './/references;add_derived_anchor()',
        './/references;check_usage()',
        './/*;insert_attribute_defaults()',  # 5.2.6.  Attribute Default Value Insertion
                                            # 5.4.6.  "pn" Numbering
        './/boilerplate//section;add_number()',
        './front//abstract;add_number()',
        './/front//note;add_number()',
        './/middle//section;add_number()',
        './/table;add_number()',
        './/figure;add_number()',
        './/references;add_number()',
        './/back//section;add_number()',
        '.;paragraph_add_numbers()',
        './/iref;add_number()',             # 5.4.7.  <iref> Numbering
        './/u;add_number()',
        './/ol;add_counter()',
        './/artset',                        #         <artwork> Processing
        './/artwork',                       # 5.5.1.  <artwork> Processing
        './/sourcecode',                    # 5.5.2.  <sourcecode> Processing
        #
        './back;insert_index()',
        './/xref',                          # 5.4.8.  <xref> Processing
        # Relref processing be handled under .//xref:
                                            # 5.4.9.  <relref> Processing
        './back;insert_author_address()',
        './/toc;insert_table_of_contents()',
        './/*[@removeInRFC="true"]',        # 5.6.1.  <note> Removal
        './/cref;removal()',                # 5.6.2.  <cref> Removal
                                            # 5.6.3.  <link> Processing
        './/link[@rel="alternate"];removal()',
        '.;check_links_required()',
        './/comment();removal()',           # 5.6.4.  XML Comment Removal
        '.;attribute_removal()',            # 5.6.5.  "xml:base" and "originalSrc" Removal
        '.;validate_after()',               # 5.6.6.  Compliance Check
        '.;insert_scripts()',               # 5.7.1.  "scripts" Insertion
        #'.;final_pi_removal()',            # Done in write().  Keep PIs when prep() is called interally
        '.;pretty_print_prep()',            # 5.7.2.  Pretty-Format
    ]

    element_contact = element_front_author
