import logging
import os
from six.moves.urllib.parse import quote, unquote
from six.moves.urllib.parse import urlparse
from six import StringIO
from six.moves.configparser import SafeConfigParser
import sys
from time import time

from pycsw.core.etree import etree
from pycsw import oaipmh, opensearch, sru
from pycsw.plugins.profiles import profile as pprofile
import pycsw.plugins.outputschemas
from pycsw.core import config, log, util
from pycsw.ogc.csw import csw2, csw3

LOGGER = logging.getLogger(__name__)


class Csw(object):
    """ Base CSW server """

    def dispatch_wsgi(self):
        """ WSGI handler """

        if hasattr(self, 'response'):
            return self._write_response()

        LOGGER.debug('WSGI mode detected')

        if self.environ['REQUEST_METHOD'] == 'POST':
            try:
                request_body_size = int(self.environ.get('CONTENT_LENGTH', 0))
            except (ValueError):
                request_body_size = 0

            self.requesttype = 'POST'
            self.request = self.environ['wsgi.input'].read(request_body_size)
            LOGGER.debug('Request type: POST.  Request:\n%s\n', self.request)

        else:  # it's a GET request
            self.requesttype = 'GET'

            scheme = '%s://' % self.environ['wsgi.url_scheme']

            if self.environ.get('HTTP_HOST'):
                url = '%s%s' % (scheme, self.environ['HTTP_HOST'])
            else:
                url = '%s%s' % (scheme, self.environ['SERVER_NAME'])

                if self.environ['wsgi.url_scheme'] == 'https':
                    if self.environ['SERVER_PORT'] != '443':
                        url += ':' + self.environ['SERVER_PORT']
                else:
                    if self.environ['SERVER_PORT'] != '80':
                        url += ':' + self.environ['SERVER_PORT']

            url += quote(self.environ.get('SCRIPT_NAME', ''))
            url += quote(self.environ.get('PATH_INFO', ''))

            if self.environ.get('QUERY_STRING'):
                url += '?' + self.environ['QUERY_STRING']

            self.request = url
            LOGGER.debug('Request type: GET.  Request:\n%s\n', self.request)

            pairs = self.environ.get('QUERY_STRING').split("&")

            kvp = {}

            for pairstr in pairs:
                pair = [unquote(a) for a in pairstr.split("=")]
                kvp[pair[0]] = pair[1] if len(pair) > 1 else ""
            self.kvp = kvp

        return self.dispatch()

    def getrecords(self):
        """ Handle GetRecords request """
        return self.iface.getrecords()

    def _cql_update_queryables_mappings(self, cql, mappings):
        """ Transform CQL query's properties to underlying DB columns """
        LOGGER.debug('Raw CQL text = %s.', cql)
        LOGGER.debug(str(list(mappings.keys())))
        if cql is not None:
            for key in mappings.keys():
                try:
                    cql = cql.replace(key, mappings[key]['dbcol'])
                except:
                    cql = cql.replace(key, mappings[key])
            LOGGER.debug('Interpolated CQL text = %s.', cql)
            return cql
