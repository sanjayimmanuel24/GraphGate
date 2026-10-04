import logging
import os
from sqlalchemy import create_engine, asc, desc, func, __version__, select
from sqlalchemy.sql import text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import create_session
from pycsw.core import util

LOGGER = logging.getLogger(__name__)


class Repository(object):
    _engines = {}

    def _create_values(self, values):
        value_dict = {}
        for num, value in enumerate(values):
            value_dict['pvalue%d' % num] = value
        return value_dict

    def query(self, constraint, sortby=None, typenames=None,
        maxrecords=10, startposition=0):
        ''' Query records from underlying repository '''

        # run the raw query and get total
        if 'where' in constraint:  # GetRecords with constraint
            LOGGER.debug('constraint detected')
            query = self.session.query(self.dataset).filter(
            text(constraint['where'])).params(self._create_values(constraint['values']))
        else:  # GetRecords sans constraint
            LOGGER.debug('No constraint detected')
            query = self.session.query(self.dataset)

        total = self._get_repo_filter(query).count()

        if util.ranking_pass:  #apply spatial ranking
            #TODO: Check here for dbtype so to extract wkt from postgis native to wkt
            LOGGER.debug('spatial ranking detected')
            LOGGER.debug('Target WKT: %s', getattr(self.dataset, self.context.md_core_model['mappings']['pycsw:BoundingBox']))
            LOGGER.debug('Query WKT: %s', util.ranking_query_geometry)
            query = query.order_by(func.get_spatial_overlay_rank(getattr(self.dataset, self.context.md_core_model['mappings']['pycsw:BoundingBox']), util.ranking_query_geometry).desc())
            #trying to make this wsgi safe
            util.ranking_pass = False
            util.ranking_query_geometry = ''

        if sortby is not None:  # apply sorting
            LOGGER.debug('sorting detected')
            #TODO: Check here for dbtype so to extract wkt from postgis native to wkt
            sortby_column = getattr(self.dataset, sortby['propertyname'])

            if sortby['order'] == 'DESC':  # descending sort
                if 'spatial' in sortby and sortby['spatial']:  # spatial sort
                    query = query.order_by(func.get_geometry_area(sortby_column).desc())
                else:  # aspatial sort
                    query = query.order_by(sortby_column.desc())
            else:  # ascending sort
                if 'spatial' in sortby and sortby['spatial']:  # spatial sort
                    query = query.order_by(func.get_geometry_area(sortby_column))
                else:  # aspatial sort
                    query = query.order_by(sortby_column)

        # always apply limit and offset
        return [str(total), self._get_repo_filter(query).limit(
        maxrecords).offset(startposition).all()]

    def _get_repo_filter(self, query):
        ''' Apply repository wide side filter / mask query '''
        if self.filter is not None:
            return query.filter(text(self.filter))
        return query
