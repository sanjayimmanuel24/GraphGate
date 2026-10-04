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
from xml2rfc.util.name import short_author_ascii_name_parts, full_author_name_expansion, short_author_name_parts
from xml2rfc.util.unicode import is_svg
from xml2rfc.utils import namespaces, find_duplicate_ids, slugify

default_silenced_messages = [
#    ".*[Pp]ostal address",
]

default_options = Namespace()
default_options.__dict__ = {
        'accept_prepped': None,
        'add_xinclude': None,
        'allow_local_file_access': False,
        'basename': None,
        'bom': False,
        'cache': None,
        'clear_cache': False,
        'css': None,
        'config_file': None,
        'country_help': False,
        'date': None,
        'datestring': None,
        'debug': False,
        'docfile': False,
        'doc_template': None,
        'doi_base_url': 'https://doi.org/',
        'draft_revisions': False,
        'dtd': None,
        'expand': False,
        'external_css': False,
        'external_js': False,
        'filename': None,
        'first_page_author_org': True,
        'html': False,
        'id_base_url': 'https://datatracker.ietf.org/doc/html/',
        'id_html_archive_url': 'https://www.ietf.org/archive/id/',
        'id_reference_base_url': 'https://datatracker.ietf.org/doc/html/',
        'id_is_work_in_progress': True,
        'image_svg': False,
        'indent': 2,
        'info': False,
        'info_base_url': 'https://www.rfc-editor.org/info/',
        'inline_version_info': True,
        'legacy': False,
        'legacy_date_format': False,
        'legacy_list_symbols': False,
        'list_symbols': ('*', '-', 'o', '+'),
        'manpage': False,
        'metadata_js_url': 'metadata.min.js',
        'no_css': False,
        'no_dtd': None,
        'no_network': False,
        'nroff': False,
        'omit_headers': None,
        'orphans': 2,
        'output_filename': None,
        'output_path': None,
        'pagination': True,
        'pi_help': False,
        'pdf': False,
        'pdf_help': False,
        'preptool': False,
        'quiet': False,
        'remove_pis': False,
        'raw': False,
        'rfc': None,
        'rfc_base_url': 'https://www.rfc-editor.org/rfc/',
        'rfc_html_archive_url': 'https://www.rfc-editor.org/rfc/',
        'rfc_local': True,
        'rfc_reference_base_url': 'https://rfc-editor.org/rfc/',
        'silence': default_silenced_messages,
        'skip_config_files': False,
        'source': None,
        'strict': False,
        'table_hyphen_breaks': False,
        'table_borders': 'full',
        'template_dir': os.path.join(os.path.dirname(os.path.dirname(__file__)), 'templates'),
        'text': True,
        'unprep': False,
        'use_bib': False,
        'utf8': False,
        'values': False,
        'verbose': False,
        'version': False,
        'v2v3': False,
        'v3': True,
        'vocabulary': 'v2',
        'widows': 2,
        'warn_bare_unicode': False,
    }


class RfcWriterError(Exception):
    """ Exception class for errors during document writing """
    def __init__(self, msg):
        self.msg = msg


class BaseV3Writer(object):

    def log(self, msg):
        xml2rfc.log.write(msg)

    def msg(self, e, label, text):
        if e != None:
            lnum = getattr(e, 'sourceline', None)
            file = getattr(e, 'base', None)
            if lnum:
                msg = "%s(%s): %s %s" % (file or self.xmlrfc.source, lnum, label, text, )
            else:
                msg = "(No source line available): %s %s" % (label, text, )
        else:
            msg = "%s %s" % (label, text)
        return msg

    def die(self, e, text, trace=False):
        msg = self.msg(e, 'Error:', text)
        self.errors.append(msg)
        raise RfcWriterError(msg)

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
            if not self.options.allow_local_file_access:
                self.check_includes()
            self.tree.xinclude()
        except etree.XIncludeError as e:
            self.die(None, "XInclude processing failed: %s" % e)

    def check_includes(self):
        # Check for <xi:include> elements with local filesystem references
        ns = {'xi':   b'http://www.w3.org/2001/XInclude'}
        xincludes = self.root.xpath('//xi:include', namespaces=ns)
        for xinclude in xincludes:
            href = urlparse(xinclude.get('href'))
            if not href.netloc or href.scheme == 'file':
                error = 'XInclude processing failed: Can not access local file: {}'.format(xinclude.get('href'))
                self.die(None, error)

    appendix_pn_re = re.compile(r'^section-[a-z]\.|^section-appendix\.')
