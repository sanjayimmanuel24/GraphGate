# Copyright The IETF Trust 2018, All Rights Reserved
# -*- coding: utf-8 -*-
from __future__ import unicode_literals, print_function, division

import io
import logging
import os
import re

try:
    import weasyprint
    import_error = None
except (ImportError, OSError, ValueError) as e:
    import_error = e
    weasyprint = False

import xml2rfc
from xml2rfc.writers.base import default_options, BaseV3Writer
from xml2rfc.writers.html import HtmlWriter
from xml2rfc.util.fonts import get_noto_serif_family_for_script

try:
    from xml2rfc import debug
    debug.debug = True
except ImportError:
    pass


class PdfWriter(BaseV3Writer):

    def pdf(self):
        if not weasyprint:
            return None

        if not self.root.get('prepTime'):
            prep = xml2rfc.PrepToolWriter(self.xmlrfc, options=self.options, date=self.options.date, liberal=True, keep_pis=[xml2rfc.V3_PI_TARGET])
            tree = prep.prep()
            self.tree = tree
            self.root = self.tree.getroot()

        self.options.no_css = True
        self.options.pdf = True
        htmlwriter = HtmlWriter(self.xmlrfc, quiet=True, options=self.options, date=self.date)
        html = htmlwriter.html()

        html = self.flatten_unicode_spans(html)

        writer = weasyprint.HTML(string=html, base_url="")

        cssin  = self.options.css or os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'xml2rfc.css')
        css = weasyprint.CSS(cssin)

        # fonts and page info
        fonts = self.get_serif_fonts()
        mono_fonts = self.get_mono_fonts()
        page_info = {
            'top-left': self.page_top_left(),
            'top-center': self.full_page_top_center(),
            'top-right': self.page_top_right(),
            'bottom-left': self.page_bottom_left(),
            'bottom-center': self.page_bottom_center(),
            'fonts': ', '.join(fonts),
            'mono-fonts': ', '.join(mono_fonts),
        }
        for (k,v) in page_info.items():
            page_info[k] = v.replace("'", r"\'")
        page_css_text = page_css_template.format(**page_info)
        page_css = weasyprint.CSS(string=page_css_text)

        pdf = writer.write_pdf(None, stylesheets=[ css, page_css ], presentational_hints=True)

        return pdf

    def write(self, filename):
        if not weasyprint:
            return

        self.filename = filename

        pdf = self.pdf()
        if pdf:
            with io.open(filename, 'bw') as file:
                file.write(pdf)
            
            if not self.options.quiet:
                self.log(' Created file %s' % filename)
        else:
            self.err(None, 'PDF creation failed')

    def flatten_unicode_spans(self, html):
        # This is a fix for bug in WeasyPrint that doesn't handle RTL unicode
        # content correctly.
        # See #873 & Kozea/WeasyPrint#1711
        return re.sub(r'<span class="unicode">(?P<unicode_content>.*?)</span>',
                      r'\g<unicode_content>',
                      html)
