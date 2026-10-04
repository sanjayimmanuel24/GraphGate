import calendar
import codecs
import copy
import datetime
import textwrap
import os
import re
import xml2rfc.log
import xml2rfc.util
import xml2rfc.utils

from lxml import etree
from argparse import Namespace
from urllib.parse import urlparse

try:
    from xml2rfc import debug
    debug.debug = True
except ImportError:
    pass

from xml2rfc import strings, log
from xml2rfc.util.date import extract_date, augment_date, format_date, get_expiry_date
from xml2rfc.util.file import can_access, FileAccessError
from xml2rfc.util.name import short_author_ascii_name_parts, full_author_name_expansion, short_author_name_parts
from xml2rfc.util.unicode import is_svg
from xml2rfc.utils import namespaces, find_duplicate_ids, slugify


class BaseV3Writer(object):

    def __init__(self, xmlrfc, quiet=None, options=default_options, date=None):
        self.xmlrfc = xmlrfc
        self.tree = xmlrfc.tree if xmlrfc else None
        self.root = self.tree.getroot() if xmlrfc else None
        self.options = options
        self.date = date if date is not None else datetime.date.today()
        self.v3_rnc_file = v3_rnc_file
        self.v3_rng_file = v3_rng_file
        self.v3_rng = etree.RelaxNG(file=self.v3_rng_file)
        self.v3_schema = v3_schema
        self.schema = v3_schema
        self.index_items = []
        self.meta_tags = set(meta_tags)
        self.text_tags = set(text_tags)
        self.inline_tags = set(inline_tags)
        self.mixed_tags = set(mixed_tags)
        self.xref_tags = set(xref_tags)
        self.attribute_defaults = self.get_all_attribute_defaults()
        #
        #
        self.errors = []

    def xinclude(self):
        ## From RFC7998:
        ##
        # 5.1.1.  XInclude Processing
        # 
        #    Process all <x:include> elements.  Note: XML <x:include> elements may
        #    include more <x:include> elements (with relative references resolved
        #    against the base URI potentially modified by a previously inserted
        #    xml:base attribute).  The tool may be configurable with a limit on
        #    the depth of recursion.
        try:
            self.check_includes()
            self.tree.xinclude()
        except etree.XIncludeError as e:
            self.die(None, "XInclude processing failed: %s" % e)

    def dispatch(self, selectors):
        """
        Process selectors, extracting an XPath selector and generating a method name
        from each entry in self.selectors, and calling the method with all elements
        matching the XPath expression, in order to process self.tree.
        """
        # Setup
        selector_visits = dict( (s, 0) for s in selectors)
        # Check for duplicate <displayreference> 'to' values:
        seen = {}
        for e in self.root.xpath('.//displayreference'):
            to = e.get('to')
            if to in set(seen.keys()):
                self.die(e, 'Found duplicate displayreference value: "%s" has already been used in %s' % (to, etree.tostring(seen[to]).strip()))
            else:
                seen[to] = e
        del seen
        ## Do remaining processing by xpath selectors (listed above)
        for s in selectors:
            slug = slugify(s.replace('self::', '').replace(' or ','_').replace(';','_'))
            if '@' in s:
                func_name = 'attribute_%s' % slug
            elif "()" in s:
                func_name = slug
            else:
                if not slug:
                    slug = 'rfc'
                func_name = 'element_%s' % slug
            # get rid of selector annotation
            ss = s.split(';')[0]
            func = getattr(self, func_name, None)
            if func:
                if self.options.debug:
                    self.note(None, "Calling %s()" % func_name)
                for e in self.tree.xpath(ss):
                    func(e, e.getparent())
                    selector_visits[s] += 1
            else:
                self.warn(None, "No handler %s() found" % (func_name, ))
        if self.options.debug:
            for s in selectors:
                if selector_visits[s] == 0:
                    self.note(None, "Selector '%s' has not matched" % (s))
        if self.errors:
            raise RfcWriterError("Not creating output file due to errors (see above)")
        return self.tree

    def validate(self, when='', warn=False):
        # Note: Our schema doesn't permit xi:include elements, so the document
        # must have had XInclude processing done before calling validate()

        # The lxml Relax NG validator checks that xsd:ID values are unique,
        # but unfortunately the error messages are completely unhelpful (lxml
        # 4.1.1, libxml 2.9.1): "Element li has extra content: t" when 't' has
        # a duplicate xsd:ID attribute.  So we check all attributes with
        # content specified as xsd:ID first, and give better messages:

        # Get the attributes we need to check
        if when and not when.startswith(' '):
            when = ' '+when
        dups = find_duplicate_ids(self.schema, self.tree)
        for attr, id, e in dups:
            self.warn(e, 'Duplicate xsd:ID attribute %s="%s" found.  This will cause validation failure.' % (attr, id, ))

        try:
            # Use a deepcopy to avoid any memory issues.
            tree = copy.deepcopy(self.tree)
            self.v3_rng.assertValid(tree)
            return True
        except Exception as e:
            deadly = False
            if hasattr(e, 'error_log'):
                for error in e.error_log:
                    path = getattr(error, 'path', '')
                    msg = "%s(%s): %s: %s, at %s" % (self.xmlrfc.source, error.line, error.level_name.title(), error.message, path)
                    self.log(msg)
                    if not deadly:
                        deadly = self.deadly_error(error)
                    if error.message.startswith("Did not expect text"):
                        items = self.tree.xpath(error.path + '/text()')
                        for item in items:
                            item = item.strip()
                            if item:
                                nl = '' if len(item) < 60 else '\n  '
                                self.log('  Unexpected text:%s "%s"' % (nl, item))

            else:
                log.warn('\nInvalid document: %s' % (e,))
            if warn and not deadly:
                self.warn(self.root, 'Invalid document%s.' % (when, ))
                return False
            else:
                self.die(self.root, 'Invalid document%s.' % (when, ))

    def validate_before(self, e, p):
        version = self.root.get('version', '3')
        if version not in ['3', ]:
            self.die(self.root, 'Expected <rfc> version="3", but found "%s"' % version)
        if not self.validate('before'):
            self.note(None, "Schema validation failed for input document")

        self.validate_draft_name()

    appendix_pn_re = re.compile(r'^section-[a-z]\.|^section-appendix\.')
