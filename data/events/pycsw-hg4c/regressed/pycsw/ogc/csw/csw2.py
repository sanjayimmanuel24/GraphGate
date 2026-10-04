import os
import sys
import cgi
from six.moves.urllib.parse import quote, unquote
from six import StringIO
from six.moves.configparser import SafeConfigParser
from pycsw.core.etree import etree
from pycsw import oaipmh, opensearch, sru
from pycsw.plugins.profiles import profile as pprofile
import pycsw.plugins.outputschemas
from pycsw.core import config, log, metadata, util
from pycsw.ogc.fes import fes1
import logging

LOGGER = logging.getLogger(__name__)


class Csw2(object):
    ''' CSW 2.x server '''
    def __init__(self, server_csw):
        ''' Initialize CSW2 '''

        self.parent = server_csw
        self.version = '2.0.2'

    def getrecords(self):
        ''' Handle GetRecords request '''

        timestamp = util.get_today_and_now()

        if ('elementsetname' not in self.parent.kvp and
            'elementname' not in self.parent.kvp):
            # mutually exclusive required
            return self.exceptionreport('MissingParameterValue',
            'elementsetname',
            'Missing one of ElementSetName or ElementName parameter(s)')

        if 'outputschema' not in self.parent.kvp:
            self.parent.kvp['outputschema'] = self.parent.context.namespaces['csw']

        if (self.parent.kvp['outputschema'] not in self.parent.context.model['operations']
            ['GetRecords']['parameters']['outputSchema']['values']):
            return self.exceptionreport('InvalidParameterValue',
            'outputschema', 'Invalid outputSchema parameter value: %s' %
            self.parent.kvp['outputschema'])

        if 'outputformat' not in self.parent.kvp:
            self.parent.kvp['outputformat'] = 'application/xml'

        if (self.parent.kvp['outputformat'] not in self.parent.context.model['operations']
            ['GetRecords']['parameters']['outputFormat']['values']):
            return self.exceptionreport('InvalidParameterValue',
            'outputformat', 'Invalid outputFormat parameter value: %s' %
            self.parent.kvp['outputformat'])

        if 'resulttype' not in self.parent.kvp:
            self.parent.kvp['resulttype'] = 'hits'

        if self.parent.kvp['resulttype'] is not None:
            if (self.parent.kvp['resulttype'] not in self.parent.context.model['operations']
            ['GetRecords']['parameters']['resultType']['values']):
                return self.exceptionreport('InvalidParameterValue',
                'resulttype', 'Invalid resultType parameter value: %s' %
                self.parent.kvp['resulttype'])

        if (('elementname' not in self.parent.kvp or
             len(self.parent.kvp['elementname']) == 0) and
             self.parent.kvp['elementsetname'] not in
             self.parent.context.model['operations']['GetRecords']['parameters']
             ['ElementSetName']['values']):
            return self.exceptionreport('InvalidParameterValue',
            'elementsetname', 'Invalid ElementSetName parameter value: %s' %
            self.parent.kvp['elementsetname'])

        if ('elementname' in self.parent.kvp and
            self.parent.requesttype == 'GET'):  # passed via GET
            self.parent.kvp['elementname'] = self.parent.kvp['elementname'].split(',')
            self.parent.kvp['elementsetname'] = 'summary'

        if 'typenames' not in self.parent.kvp:
            return self.exceptionreport('MissingParameterValue',
            'typenames', 'Missing typenames parameter')

        if ('typenames' in self.parent.kvp and
            self.parent.requesttype == 'GET'):  # passed via GET
            self.parent.kvp['typenames'] = self.parent.kvp['typenames'].split(',')

        if 'typenames' in self.parent.kvp:
            for tname in self.parent.kvp['typenames']:
                if (tname not in self.parent.context.model['operations']['GetRecords']
                    ['parameters']['typeNames']['values']):
                    return self.exceptionreport('InvalidParameterValue',
                    'typenames', 'Invalid typeNames parameter value: %s' %
                    tname)

        # check elementname's
        if 'elementname' in self.parent.kvp:
            for ename in self.parent.kvp['elementname']:
                enamelist = self.parent.repository.queryables['_all'].keys()
                if ename not in enamelist:
                    return self.exceptionreport('InvalidParameterValue',
                    'elementname', 'Invalid ElementName parameter value: %s' %
                    ename)

        if self.parent.kvp['resulttype'] == 'validate':
            return self._write_acknowledgement()

        maxrecords_cfg = -1  # not set in config server.maxrecords

        if self.parent.config.has_option('server', 'maxrecords'):
            maxrecords_cfg = int(self.parent.config.get('server', 'maxrecords'))

        if 'maxrecords' not in self.parent.kvp:  # not specified by client
            if maxrecords_cfg > -1:  # specified in config
                self.parent.kvp['maxrecords'] = maxrecords_cfg
            else:  # spec default
                self.parent.kvp['maxrecords'] = 10
        else:  # specified by client
            if self.parent.kvp['maxrecords'] == '':
                self.parent.kvp['maxrecords'] = 10
            if maxrecords_cfg > -1:  # set in config
                if int(self.parent.kvp['maxrecords']) > maxrecords_cfg:
                    self.parent.kvp['maxrecords'] = maxrecords_cfg

        if any(x in ['bbox', 'q', 'time'] for x in self.parent.kvp):
            LOGGER.debug('OpenSearch Geo/Time parameters detected.')
            self.parent.kvp['constraintlanguage'] = 'FILTER'
            tmp_filter = opensearch.kvp2filterxml(self.parent.kvp, self.parent.context)
            if tmp_filter is not "":
                self.parent.kvp['constraint'] = tmp_filter
                LOGGER.debug('OpenSearch Geo/Time parameters to Filter: %s.', self.parent.kvp['constraint'])

        if self.parent.requesttype == 'GET':
            if 'constraint' in self.parent.kvp:
                # GET request
                LOGGER.debug('csw:Constraint passed over HTTP GET.')
                if 'constraintlanguage' not in self.parent.kvp:
                    return self.exceptionreport('MissingParameterValue',
                    'constraintlanguage',
                    'constraintlanguage required when constraint specified')
                if (self.parent.kvp['constraintlanguage'] not in
                self.parent.context.model['operations']['GetRecords']['parameters']
                ['CONSTRAINTLANGUAGE']['values']):
                    return self.exceptionreport('InvalidParameterValue',
                    'constraintlanguage', 'Invalid constraintlanguage: %s'
                    % self.parent.kvp['constraintlanguage'])
                if self.parent.kvp['constraintlanguage'] == 'CQL_TEXT':
                    tmp = self.parent.kvp['constraint']
                    self.parent.kvp['constraint'] = {}
                    self.parent.kvp['constraint']['type'] = 'cql'
                    self.parent.kvp['constraint']['where'] = \
                    self.parent._cql_update_queryables_mappings(tmp,
                    self.parent.repository.queryables['_all'])
                    self.parent.kvp['constraint']['values'] = {}
                elif self.parent.kvp['constraintlanguage'] == 'FILTER':
                    # validate filter XML
                    try:
                        schema = os.path.join(self.parent.config.get('server', 'home'),
                        'core', 'schemas', 'ogc', 'filter', '1.1.0', 'filter.xsd')
                        LOGGER.debug('Validating Filter %s.', self.parent.kvp['constraint'])
                        schema = etree.XMLSchema(file=schema)
                        parser = etree.XMLParser(schema=schema, resolve_entities=False)
                        doc = etree.fromstring(self.parent.kvp['constraint'], parser)
                        LOGGER.debug('Filter is valid XML.')
                        self.parent.kvp['constraint'] = {}
                        self.parent.kvp['constraint']['type'] = 'filter'
                        self.parent.kvp['constraint']['where'], self.parent.kvp['constraint']['values'] = \
                        fes1.parse(doc,
                        self.parent.repository.queryables['_all'],
                        self.parent.repository.dbtype,
                        self.parent.context.namespaces, self.parent.orm, self.parent.language['text'], self.parent.repository.fts)
                    except Exception as err:
                        errortext = \
                        'Exception: document not valid.\nError: %s.' % str(err)

                        LOGGER.error(errortext)
                        return self.exceptionreport('InvalidParameterValue',
                        'constraint', 'Invalid Filter query: %s' % errortext)
            else:
                self.parent.kvp['constraint'] = {}

        if 'sortby' not in self.parent.kvp:
            self.parent.kvp['sortby'] = None
        elif 'sortby' in self.parent.kvp and self.parent.requesttype == 'GET':
            LOGGER.debug('Sorted query specified.')
            tmp = self.parent.kvp['sortby']
            self.parent.kvp['sortby'] = {}

            try:
                name, order = tmp.rsplit(':', 1)
            except:
                return self.exceptionreport('InvalidParameterValue',
                'sortby', 'Invalid SortBy value: must be in the format\
                propertyname:A or propertyname:D')

            try:
                self.parent.kvp['sortby']['propertyname'] = \
                self.parent.repository.queryables['_all'][name]['dbcol']
                if name.find('BoundingBox') != -1 or name.find('Envelope') != -1:
                    # it's a spatial sort
                    self.parent.kvp['sortby']['spatial'] = True
            except Exception as err:
                return self.exceptionreport('InvalidParameterValue',
                'sortby', 'Invalid SortBy propertyname: %s' % name)

            if order not in ['A', 'D']:
                return self.exceptionreport('InvalidParameterValue',
                'sortby', 'Invalid SortBy value: sort order must be "A" or "D"')

            if order == 'D':
                self.parent.kvp['sortby']['order'] = 'DESC'
            else:
                self.parent.kvp['sortby']['order'] = 'ASC'

        if 'startposition' not in self.parent.kvp:
            self.parent.kvp['startposition'] = 1

        # query repository
        LOGGER.debug('Querying repository with constraint: %s,\
        sortby: %s, typenames: %s, maxrecords: %s, startposition: %s.',
        self.parent.kvp['constraint'], self.parent.kvp['sortby'], self.parent.kvp['typenames'],
        self.parent.kvp['maxrecords'], self.parent.kvp['startposition'])

        try:
            matched, results = self.parent.repository.query(
            constraint=self.parent.kvp['constraint'],
            sortby=self.parent.kvp['sortby'], typenames=self.parent.kvp['typenames'],
            maxrecords=self.parent.kvp['maxrecords'],
            startposition=int(self.parent.kvp['startposition'])-1)
        except Exception as err:
            return self.exceptionreport('InvalidParameterValue', 'constraint',
            'Invalid query: %s' % err)

        dsresults = []

        if (self.parent.config.has_option('server', 'federatedcatalogues') and
            'distributedsearch' in self.parent.kvp and
            self.parent.kvp['distributedsearch'] and self.parent.kvp['hopcount'] > 0):
            # do distributed search

            LOGGER.debug('DistributedSearch specified (hopCount: %s).',
            self.parent.kvp['hopcount'])

            from owslib.csw import CatalogueServiceWeb
            from owslib.ows import ExceptionReport
            for fedcat in \
            self.parent.config.get('server', 'federatedcatalogues').split(','):
                LOGGER.debug('Performing distributed search on federated \
                catalogue: %s.', fedcat)
                remotecsw = CatalogueServiceWeb(fedcat, skip_caps=True)
                try:
                    remotecsw.getrecords2(xml=self.parent.request,
                                          esn=self.parent.kvp['elementsetname'],
                                          outputschema=self.parent.kvp['outputschema'])
                    if hasattr(remotecsw, 'results'):
                        LOGGER.debug(
                        'Distributed search results from catalogue \
                        %s: %s.', fedcat, remotecsw.results)

                        remotecsw_matches = int(remotecsw.results['matches'])
                        plural = 's' if remotecsw_matches != 1 else ''
                        if remotecsw_matches > 0:
                            matched = str(int(matched) + remotecsw_matches)
                            dsresults.append(etree.Comment(
                            ' %d result%s from %s ' %
                            (remotecsw_matches, plural, fedcat)))

                            dsresults.append(remotecsw.records)
                except ExceptionReport as err:
                    error_string = 'remote CSW %s returned exception: ' % fedcat
                    dsresults.append(etree.Comment(
                    ' %s\n\n%s ' % (error_string, err)))
                    LOGGER.error(error_string, exc_info=True)
                except Exception as err:
                    error_string = 'remote CSW %s returned error: ' % fedcat
                    dsresults.append(etree.Comment(
                    ' %s\n\n%s ' % (error_string, err)))
                    LOGGER.error(error_string, exc_info=True)

        if int(matched) == 0:
            returned = nextrecord = '0'
        else:
            if int(matched) < int(self.parent.kvp['maxrecords']):
                returned = matched
                nextrecord = '0'
            else:
                returned = str(self.parent.kvp['maxrecords'])
                if int(self.parent.kvp['startposition']) + int(self.parent.kvp['maxrecords']) >= int(matched):
                    nextrecord = '0'
                else:
                    nextrecord = str(int(self.parent.kvp['startposition']) + \
                    int(self.parent.kvp['maxrecords']))

        LOGGER.debug('Results: matched: %s, returned: %s, next: %s.',
        matched, returned, nextrecord)

        node = etree.Element(util.nspath_eval('csw:GetRecordsResponse',
        self.parent.context.namespaces),
        nsmap=self.parent.context.namespaces, version='2.0.2')

        node.attrib[util.nspath_eval('xsi:schemaLocation',
        self.parent.context.namespaces)] = \
        '%s %s/csw/2.0.2/CSW-discovery.xsd' % \
        (self.parent.context.namespaces['csw'], self.parent.config.get('server', 'ogc_schemas_base'))

        if 'requestid' in self.parent.kvp and self.parent.kvp['requestid'] is not None:
            etree.SubElement(node, util.nspath_eval('csw:RequestId',
            self.parent.context.namespaces)).text = self.parent.kvp['requestid']

        etree.SubElement(node, util.nspath_eval('csw:SearchStatus',
        self.parent.context.namespaces), timestamp=timestamp)

        if 'where' not in self.parent.kvp['constraint'] and \
        self.parent.kvp['resulttype'] is None:
            returned = '0'

        searchresults = etree.SubElement(node,
        util.nspath_eval('csw:SearchResults', self.parent.context.namespaces),
        numberOfRecordsMatched=matched, numberOfRecordsReturned=returned,
        nextRecord=nextrecord, recordSchema=self.parent.kvp['outputschema'])

        if self.parent.kvp['elementsetname'] is not None:
            searchresults.attrib['elementSet'] = self.parent.kvp['elementsetname']

        if 'where' not in self.parent.kvp['constraint'] \
        and self.parent.kvp['resulttype'] is None:
            LOGGER.debug('Empty result set returned.')
            return node

        if self.parent.kvp['resulttype'] == 'hits':
            return node


        if results is not None:
            if len(results) < int(self.parent.kvp['maxrecords']):
                max1 = len(results)
            else:
                max1 = int(self.parent.kvp['startposition']) + (int(self.parent.kvp['maxrecords'])-1)
            LOGGER.debug('Presenting records %s - %s.',
            self.parent.kvp['startposition'], max1)

            for res in results:
                try:
                    if (self.parent.kvp['outputschema'] ==
                        'http://www.opengis.net/cat/csw/2.0.2' and
                        'csw:Record' in self.parent.kvp['typenames']):
                        # serialize csw:Record inline
                        searchresults.append(self._write_record(
                        res, self.parent.repository.queryables['_all']))
                    elif (self.parent.kvp['outputschema'] ==
                        'http://www.opengis.net/cat/csw/2.0.2' and
                        'csw:Record' not in self.parent.kvp['typenames']):
                        # serialize into csw:Record model

                        for prof in self.parent.profiles['loaded']:
                            # find source typename
                            if self.parent.profiles['loaded'][prof].typename in \
                            self.parent.kvp['typenames']:
                                typename = self.parent.profiles['loaded'][prof].typename
                                break

                        util.transform_mappings(self.parent.repository.queryables['_all'],
                        self.parent.context.model['typenames'][typename]\
                        ['mappings']['csw:Record'], reverse=True)

                        searchresults.append(self._write_record(
                        res, self.parent.repository.queryables['_all']))
                    elif self.parent.kvp['outputschema'] in self.parent.outputschemas.keys():  # use outputschema serializer
                        searchresults.append(self.parent.outputschemas[self.parent.kvp['outputschema']].write_record(res, self.parent.kvp['elementsetname'], self.parent.context, self.parent.config.get('server', 'url')))
                    else:  # use profile serializer
                        searchresults.append(
                        self.parent.profiles['loaded'][self.parent.kvp['outputschema']].\
                        write_record(res, self.parent.kvp['elementsetname'],
                        self.parent.kvp['outputschema'],
                        self.parent.repository.queryables['_all']))
                except Exception as err:
                    self.parent.response = self.exceptionreport(
                    'NoApplicableCode', 'service',
                    'Record serialization failed: %s' % str(err))
                    return self.parent.response

        if len(dsresults) > 0:  # return DistributedSearch results
            for resultset in dsresults:
                if isinstance(resultset, etree._Comment):
                    searchresults.append(resultset)
                for rec in resultset:
                    searchresults.append(etree.fromstring(resultset[rec].xml, self.parent.context.parser))

        if 'responsehandler' in self.parent.kvp:  # process the handler
            self.parent._process_responsehandler(etree.tostring(node,
            pretty_print=self.parent.pretty_print))
        else:
            return node

    def exceptionreport(self, code, locator, text):
        ''' Generate ExceptionReport '''
        self.parent.exception = True
        self.parent.status = 'OK'

        try:
            language = self.parent.config.get('server', 'language')
            ogc_schemas_base = self.parent.config.get('server', 'ogc_schemas_base')
        except:
            language = 'en-US'
            ogc_schemas_base = self.parent.context.ogc_schemas_base

        node = etree.Element(util.nspath_eval('ows:ExceptionReport',
        self.parent.context.namespaces), nsmap=self.parent.context.namespaces,
        version='1.2.0', language=language)

        node.attrib[util.nspath_eval('xsi:schemaLocation',
        self.parent.context.namespaces)] = \
        '%s %s/ows/1.0.0/owsExceptionReport.xsd' % \
        (self.parent.context.namespaces['ows'], ogc_schemas_base)

        exception = etree.SubElement(node, util.nspath_eval('ows:Exception',
        self.parent.context.namespaces),
        exceptionCode=code, locator=locator)

        exception_text = etree.SubElement(exception,
        util.nspath_eval('ows:ExceptionText',
        self.parent.context.namespaces))

        try:
            exception_text.text = text
        except ValueError as err:
            exception_text.text = repr(text)

        return node
