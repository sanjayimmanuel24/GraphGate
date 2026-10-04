# Copyright The IETF Trust 2018, All Rights Reserved
# -*- coding: utf-8 -*-
from __future__ import unicode_literals, print_function, division

import lxml
import os
import re
import unicodedata
import xml2rfc

from contextlib import closing
from io import open
from lxml.html import html_parser
from lxml.html.builder import ElementMaker

from urllib.request import urlopen
from urllib.parse import urlparse, urljoin

try:
    from xml2rfc import debug
    debug.debug = True
except ImportError:
    pass

from xml2rfc import log, strings
from xml2rfc.writers.base import default_options, BaseV3Writer, RfcWriterError, SUBSERIES
from xml2rfc.uniscripts import is_script
from xml2rfc.util.date import extract_date, augment_date, format_date, format_date_iso, get_expiry_date
from xml2rfc.util.name import ( full_author_name_expansion, short_author_role,
                                ref_author_name_first, ref_author_name_last, 
                                short_author_name_set, full_author_name_set,
                                short_org_name_set, full_org_name, )
from xml2rfc.util.postal import ( get_normalized_address_info, address_hcard_properties,
                                get_address_format_rules, address_field_mapping, )
from xml2rfc.util.unicode import expand_unicode_element
from xml2rfc.utils import namespaces, is_htmlblock, find_duplicate_html_ids, sdict, clean_text


class HtmlWriter(BaseV3Writer):

    def html_tree(self):
        if not self.root.get('prepTime'):
            prep = xml2rfc.PrepToolWriter(self.xmlrfc, options=self.options, date=self.options.date, liberal=True, keep_pis=[xml2rfc.V3_PI_TARGET])
            tree = prep.prep()
            self.tree = tree
            self.root = self.tree.getroot()
        html_tree = self.render(None, self.root)
        html_tree = self.post_process(html_tree)
        return html_tree

    def html(self, html_tree=None):
        if html_tree is None:
            html_tree = self.html_tree()
        # 6.1.  DOCTYPE
        # 
        #    The DOCTYPE of the document is "html", which declares that the
        #    document is compliant with HTML5.  The document will start with
        #    exactly this string:
        # 
        #    <!DOCTYPE html>
        html = lxml.etree.tostring(html_tree, method='html', encoding='unicode', pretty_print=True, doctype="<!DOCTYPE html>")
        html = re.sub(r'[\x00-\x09\x0B-\x1F]+', ' ', html)
        return html

    def render(self, h, x):
        res = None
        if x.tag in (lxml.etree.PI, lxml.etree.Comment):
            tail = x.tail if x.tail and x.tail.strip() else ''
            if len(h):
                last = h[-1]
                last.tail = (last.tail or '') + tail
            else:
                h.text = (h.text or '') + tail
        else:
            func_name = "render_%s" % (x.tag.lower(),)
            func = getattr(self, func_name, None)
            if func == None:
                func = self.default_renderer
                if x.tag in self.__class__.deprecated_element_tags:
                    self.warn(x, "Was asked to render a deprecated element: <%s>", (x.tag, ))
                elif not x.tag in seen:
                    self.warn(x, "No renderer for <%s> found" % (x.tag, ))
                    seen.add(x.tag)
            res = func(h, x)
        return res

    def default_renderer(self, h, x):
        hh = add(x.tag, h, x)
        for c in x.getchildren():
            self.render(hh, c)
        return hh

    def skip_renderer(self, h, x):
        part = self.part
        for c in x.getchildren():
            self.part = part
            self.render(h, c)

    def null_renderer(self, h, x):
        return None

    def render_rfc(self, h, x):
        self.part = x.tag
    # 6.2.  Root Element
    # 
    #    The root element of the document is <html>.  This element includes a
    #    "lang" attribute, whose value is a language tag, as discussed in
    #    [RFC5646], that describes the natural language of the document.  The
    #    language tag to be included is "en".  The class of the <html> element
    #    will be copied verbatim from the XML <rfc> element's <front>
    #    element's <seriesInfo> element's "name" attributes (separated by
    #    spaces; see Section 2.47.3 of [RFC7991]), allowing CSS to style RFCs
    #    and Internet-Drafts differently from one another (if needed):
    # 
    #    <html lang="en" class="RFC">

        classes = ' '.join( i.get('name') for i in x.xpath('./front/seriesInfo') )
        #
        html = h if h != None else build.html(classes=classes, lang='en')
        self.html_root = html

    # 6.3.  <head> Element
    # 
    #    The root <html> will contain a <head> element that contains the
    #    following elements, as needed.

        head = add.head(html, None)

    # 6.3.1.  Charset Declaration
    # 
    #    In order to be correctly processed by browsers that load the HTML
    #    using a mechanism that does not provide a valid content-type or
    #    charset (such as from a local file system using a "file:" URL), the
    #    HTML <head> element contains a <meta> element, whose "charset"
    #    attribute value is "utf-8":
    # 
    #    <meta charset="utf-8">

        add.meta(head, None, charset='utf-8')
        add.meta(head, None, name="scripts", content=x.get('scripts'))
        add.meta(head, None, name="viewport", content="initial-scale=1.0")

    # 6.3.2.  Document Title
    # 
    #    The contents of the <title> element from the XML source will be
    #    placed inside an HTML <title> element in the header.

        title = x.find('./front/title')
        text = clean_text(' '.join(title.itertext()))
        if self.options.rfc:
            text = ("RFC %s: " % self.root.get('number')) + text
        add.title(head, None, text)

    # 6.3.3.  Document Metadata
    # 
    #    The following <meta> elements will be included:
    # 
    #    o  author - one each for the each of the "fullname"s and
    #       "asciiFullname"s of all of the <author>s from the <front> of the
    #       XML source
        for a in x.xpath('./front/author'):
            name = full_author_name_expansion(a) or full_org_name(a)
            add.meta(head, None, name='author', content=name )

    #    o  description - the <abstract> from the XML source

        abstract = x.find('./front/abstract')
        if abstract != None:
            abstract_text = ' '.join(abstract.itertext())
            add.meta(head, None, name='description', content=abstract_text)

    #    o  generator - the name and version number of the software used to
    #       create the HTML

        generator = "%s %s" % (xml2rfc.NAME, xml2rfc.__version__)
        add.meta(head, None, name='generator', content=generator)
        
    #    o  keywords - comma-separated <keyword>s from the XML source

        for keyword in x.xpath('./front/keyword'):
            add.meta(head, None, name='keyword', content=keyword.text)

    ## Additional meta information, not specified in RFC 7992:
        if self.options.rfc:
            add.meta(head, None, name='rfc.number', content=self.root.get('number'))
        else:
            add.meta(head, None, name='ietf.draft', content=self.root.get('docName'))

        if self.options.inline_version_info:
            versions = lxml.etree.Comment(' Generator version information:\n  '
                    +('\n    '.join(['%s %s'%v for v in xml2rfc.get_versions()]) )
                    +'\n'
                )
            versions.tail = '\n'
            head.append(versions)

    #    For example:
    # 
    #    <meta name="author" content="Joe Hildebrand">
    #    <meta name="author" content="JOE HILDEBRAND">
    #    <meta name="author" content="Heather Flanagan">
    #    <meta name="description" content="This document defines...">
    #    <meta name="generator" content="xmljade v0.2.4">
    #    <meta name="keywords" content="html,css,rfc">
    # 
    #    Note: the HTML <meta> tag does not contain a closing slash.
    # 
    # 6.3.4.  Link to XML Source
    # 
    #    The <head> element contains a <link> tag, with "rel" attribute of
    #    "alternate", "type" attribute of "application/rfc+xml", and "href"
    #    attribute pointing to the prepared XML source that was used to
    #    generate this document.
    # 
    #    <link rel="alternate" type="application/rfc+xml" href="source.xml">

        add.link(head, None, href=os.path.basename(self.xmlrfc.source), rel='alternate', type='application/rfc+xml')

    # 6.3.5.  Link to License
    # 
    #    The <head> element contains a <link> tag, with "rel" attribute of
    #    "license" and "href" attribute pointing to the an appropriate
    #    copyright license for the document.
    # 
    #    <link rel="license"
    #       href="https://trustee.ietf.org/trust-legal-provisions.html">

        add.link(head, None, href="#copyright", rel='license')

    # 6.3.6.  Style
    # 
    #    The <head> element contains an embedded CSS in a <style> element.
    #    The styles in the style sheet are to be set consistently between
    #    documents by the RFC Editor, according to the best practices of the
    #    day.
    # 
    #    To ensure consistent formatting, individual style attributes should
    #    not be used in the main portion of the document.
    # 
    #    Different readers of a specification will desire different formatting
    #    when reading the HTML versions of RFCs.  To facilitate this, the
    #    <head> element also includes a <link> to a style sheet in the same
    #    directory as the HTML file, named "rfc-local.css".  Any formatting in
    #    the linked style sheet will override the formatting in the included
    #    style sheet.  For example:
    # 
    #    <style>
    #      body {}
    #      ...
    #    </style>
    #    <link rel="stylesheet" type="text/css" href="rfc-local.css">

        data_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')
        
        css = None
        self.css_js = os.path.join(data_dir, 'xml2rfc.js')
        if self.options.css:
            css, cssin = self.read_css(data_dir, self.options.css)
        if not css:
            cssin = os.path.join(data_dir, 'xml2rfc.css')
            with open(cssin, encoding='utf-8') as f:
                css = f.read()
        else:
            jsin = os.path.splitext(cssin)[0] + '.js'
            if os.path.exists(jsin):
                self.css_js = jsin

        if self.options.external_css:
            cssout = os.path.join(os.path.dirname(self.filename), 'xml2rfc.css')
            with open(cssout, 'w', encoding='utf-8') as f:
                f.write(css)
            add.link(head, None, href="xml2rfc.css", rel="stylesheet")
        elif self.options.no_css:
            pass
        else:
            add.style(head, None, css, type="text/css")

        if self.options.rfc_local and (not self.options.pdf or os.path.exists('rfc-local.css')):
            add.link(head, None, href="rfc-local.css", rel="stylesheet", type="text/css")

    # 6.3.7.  Links
    # 
    #    Each <link> element from the XML source is copied into the HTML
    #    header.  Note: the HTML <link> element does not include a closing
    #    slash.

        for link in x.xpath('./link'):
            head.append(link)

        body = add.body(html, None, classes='xml2rfc')

        scheme = urlparse(self.options.metadata_js_url).scheme
        if scheme in ['http', 'https', 'ftp', 'file', ]:
            with closing(urlopen(self.options.metadata_js_url)) as f:
                js = f.read()
        elif scheme:
            self.err(x, "Cannot handle scheme: %s in --metadata-js-url value" % scheme)
            js = ''
        else:
            jsin = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', self.options.metadata_js_url)
            with open(jsin) as f:
                js = f.read()

        if js:
            if self.filename:
                dest_dir = os.path.dirname(self.filename)
                if dest_dir:
                    dest_dir += os.sep
                jsout = urljoin(dest_dir, self.options.metadata_js_url)
                # Only write to the destination if it's a local file:
                if not urlparse(jsout).scheme and jsout.startswith(dest_dir):
                    if self.options.external_js:
                        try:
                            with open(jsout, 'w', encoding='utf-8') as f:
                                f.write(js)
                        except IOError as exception:
                            log.warn("Could not write to %s: %s" % (jsout, exception))
                    else:
                        add.script(head, None, js, type="application/javascript")
            if self.options.metadata_js_url and (
                urlparse(self.options.metadata_js_url).scheme
                or self.options.external_js
            ):
                # Add external script tag
                s = add.script(body, None, src=self.options.metadata_js_url)
                s.tail = '\n'

    # 6.4.  Page Headers and Footers
    # 
    #    In order to simplify printing by HTML renderers that implement
    #    [W3C.WD-css3-page-20130314], a hidden HTML <table> tag of class
    #    "ears" is added at the beginning of the HTML <body> tag, containing
    #    HTML <thead> and <tfoot> tags, each of which contains an HTML <tr>
    #    tag, which contains three HTML <td> tags with class "left", "center",
    #    and "right", respectively.
    # 
    #    The <thead> corresponds to the top of the page, the <tfoot> to the
    #    bottom.  The string "[Page]" can be used as a placeholder for the
    #    page number.  In practice, this must always be in the <tfoot>'s right
    #    <td>, and no control of the formatting of the page number is implied.
    #
    #    <table class="ears">
    #      <thead>
    #        <tr>
    #          <td class="left">Internet-Draft</td>
    #          <td class="center">HTML RFC</td>
    #          <td class="right">March 2016</td>
    #        </tr>
    #      </thead>
    #      <tfoot>
    #        <tr>
    #          <td class="left">Hildebrand</td>
    #          <td class="center">Expires September 2, 2016</td>
    #          <td class="right">[Page]</td>
    #        </tr>
    #      </tfoot>
    #    </table>

        body.append(
            build.table(
                build.thead(
                    build.tr(
                        build.td(self.page_top_left(), classes='left'),
                        build.td(self.page_top_center(), classes='center'),
                        build.td(self.page_top_right(), classes='right'),
                    ),
                ),
                build.tfoot(
                    build.tr(
                        build.td(self.page_bottom_left(), classes='left'),
                        build.td(self.page_bottom_center(), classes='center'),
                        build.td("[Page]", classes='right'),
                    ),
                ),
                classes='ears',
            )
        )

        for c in [ e for e in [ x.find('front'), x.find('middle'), x.find('back') ] if e != None]:
            self.part = c.tag
            self.render(body, c)

        with open(self.css_js, encoding='utf-8') as f:
            js = f.read()
        add.script(body, None, js)

        return html

    ## The above text is reasonable for author name and org, but nonsense for
    ## the <address> element.  The following text will be used:
    ##
    ## The <address> element will be rendered as a sequence of <div> elements,
    ## each corresponding to a child element of <address>.  Element classes
    ## will be taken from hcard, as specified on http://microformats.org/wiki/hcard
    ## 
    ##   <address class="vcard">
    ##
    ##     <!-- ... name, role, and organization elements ... -->
    ##
    ##      <div class="adr">
    ##        <div class="street-address">1 Main Street</div>
    ##        <div class="street-address">Suite 1</div>
    ##        <div class="city-region-code">
    ##          <span class="city">Denver</span>,&nbsp;
    ##          <span class="region">CO</span>&nbsp;
    ##          <span class="postal-code">80202</span>
    ##        </div>
    ##        <div class="country-name">USA</div>
    ##      </div>
    ##      <div class="tel">
    ##        <span>Phone:</span>
    ##        <a class="tel" href="tel:+1-720-555-1212">+1-720-555-1212</a>
    ##      </div>
    ##      <div class="fax">
    ##        <span>Fax:</span>
    ##        <span class="tel">+1-303-555-1212</span>
    ##      </div>
    ##      <div class="email">
    ##        <span>Email:</span>
    ##        <a class="email" href="mailto:author@example.com">author@example.com</a>
    ##      </div>
    ##    </address>
    render_address = skip_renderer

    # 9.6.  <aside>
    # 
    #    This element is rendered as an HTML <aside> element, with all child
    #    content appropriately transformed.
    # 
    #    <aside id="s-2.1-2">
    #      <p id="s-2.1-2.1">
    #        A little more than kin, and less than kind.
    #        <a class="pilcrow" href="#s-2.1-2.1">&para;</a>
    #      </p>
    #    </aside>
    render_aside = default_renderer

    render_contact = render_author

    # 9.8.  <back>
    # 
    #    If there is exactly one <references> child, render that child in a
    #    similar way to a <section>.  If there are more than one <references>
    #    children, render as a <section> whose name is "References",
    #    containing a <section> for each <references> child.
    # 
    #    After any <references> sections, render each <section> child of
    #    <back> as an appendix.
    # 
    #    <section id="n-references">
    #      <h2 id="s-2">
    #        <a class="selfRef" href="#s-2">2.</a>
    #        <a class="selfRef" href="#n-references">References</a>
    #      </h2>
    #      <section id="n-normative">
    #        <h3 id="s-2.1">
    #          <a class="selfRef" href="#s-2.1">2.1.</a>
    #          <a class="selfRef" href="#n-normative">Normative</a>
    #        </h3>
    #        <dl class="reference"></dl>
    #      </section>
    #      <section id="n-informational">
    #        <h3 id="s-2.2">
    #          <a class="selfRef" href="#s-2.2">2.2.</a>
    #          <a class="selfRef" href="#n-informational">Informational</a>
    #        </h3>
    #        <dl class="reference"></dl>
    #      </section>
    #    </section>
    #    <section id="n-unimportant">
    #      <h2 id="s-A">
    #        <a class="selfRef" href="#s-A">Appendix A.</a>
    #        <a class="selfRef" href="#n-unimportant">Unimportant</a>
    #      </h2>
    #    </section>
    render_back = skip_renderer

    # 9.11.  <boilerplate>
    # 
    #    The Status of This Memo and the Copyright statement, together
    #    commonly referred to as the document boilerplate, appear after the
    #    Abstract.  The children of the input <boilerplate> element are
    #    treated in a similar fashion to unnumbered sections.
    # 
    #    <section id="status-of-this-memo">
    #      <h2 id="s-boilerplate-1">
    #        <a href="#status-of-this-memo" class="selfRef">
    #          Status of this Memo</a>
    #      </h2>
    #      <p id="s-boilerplate-1-1">This Internet-Draft is submitted in full
    #        conformance with the provisions of BCP 78 and BCP 79.
    #        <a href="#s-boilerplate-1-1" class="pilcrow">&para;</a>
    #      </p>
    #    ...
    render_boilerplate = skip_renderer

    # 9.19.  <displayreference>
    # 
    #    This element does not affect the HTML output, but it is used in the
    #    generation of the <reference>, <referencegroup>, <relref>, and <xref>
    #    elements.
    render_displayreference = null_renderer

    # 9.21.  <dt>
    # 
    #    This element is directly rendered as its HTML counterpart.
    render_dt = default_renderer

    # 
    # 9.22.  <em>
    # 
    #    This element is directly rendered as its HTML counterpart.
    render_em = default_renderer

    # 9.31.  <middle>
    # 
    #    This element does not add any direct output to HTML.
    render_middle = skip_renderer

    # 9.35.  <organization>
    # 
    #    This element is rendered as an HTML <div> tag with CSS class "org".
    # 
    #    If the element contains the "ascii" attribute, the organization name
    #    is rendered twice: once with the non-ASCII version wrapped in an HTML
    #    <span> tag of class "non-ascii" and then as the ASCII version wrapped
    #    in an HTML <span> tag of class "ascii" wrapped in parentheses.
    # 
    #    <div class="org">
    #      <span class="non-ascii">Test Org</span>
    #      (<span class="ascii">TEST ORG</span>)
    #    </div>
    render_organization = null_renderer # handled in render_address

    # 9.50.  <strong>
    # 
    #    This element is directly rendered as its HTML counterpart.
    render_strong = default_renderer

    # 9.51.  <sub>
    # 
    #    This element is directly rendered as its HTML counterpart.
    render_sub = default_renderer

    # 9.52.  <sup>
    # 
    #    This element is directly rendered as its HTML counterpart.
    render_sup = default_renderer

    # 9.55.  <tbody>
    # 
    #    This element is directly rendered as its HTML counterpart.
    render_tbody = default_renderer

    # 9.57.  <tfoot>
    # 
    #    This element is directly rendered as its HTML counterpart.
    render_tfoot = default_renderer

    # 9.59.  <thead>
    #
    #    This element is directly rendered as its HTML counterpart.
    render_thead = default_renderer

    # <toc>
    render_toc = skip_renderer

    # 9.61.  <tr>
    # 
    #    This element is directly rendered as its HTML counterpart.
    render_tr = default_renderer

    # 9.65.  <workgroup>
    # 
    #    This element does not add any direct output to HTML.
    render_workgroup = null_renderer    # handled in render_rfc, when rendering the page top for drafts
