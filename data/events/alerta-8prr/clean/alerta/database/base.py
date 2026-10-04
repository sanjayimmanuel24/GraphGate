from importlib import import_module
from importlib.metadata import entry_points as _entry_points
from typing import NamedTuple
from urllib.parse import urlparse

from flask import g


class Query(NamedTuple):
    where: str
    sort: str
    group: str


class Base:
    pass


def get_backend(app):
    db_uri = app.config['DATABASE_URL']
    backend = urlparse(db_uri).scheme

    if backend.startswith('mongodb'):
        backend = 'mongodb'
    if backend == 'postgresql':
        backend = 'postgres'
    return backend


def load_backend(backend):
    try:
        eps = _entry_points(group='alerta.database.backends')
    except TypeError:
        eps = _entry_points().get('alerta.database.backends', [])
    for ep in eps:
        if ep.name == backend:
            module_name = ep.value.split(':')[0]
            break
    else:
        module_name = f'alerta.database.backends.{backend}'

    try:
        return import_module(module_name)
    except Exception:
        raise ImportError(f'Failed to load {backend} database backend')


class Database(Base):

    def __init__(self, app=None):
        self.app = None
        if app is not None:
            self.init_db(app)

    def init_db(self, app):
        backend = get_backend(app)
        cls = load_backend(backend)
        self.__class__ = type('DatabaseImpl', (cls.Backend, Database), {})

        try:
            self.create_engine(app, uri=app.config['DATABASE_URL'], dbname=app.config['DATABASE_NAME'], schema=app.config['DATABASE_SCHEMA'],
                               raise_on_error=app.config['DATABASE_RAISE_ON_ERROR'])
        except Exception as e:
            if app.config['DATABASE_RAISE_ON_ERROR']:
                raise
            app.logger.warning(e)

        app.teardown_appcontext(self.teardown_db)

    def get_db(self):
        if 'db' not in g:
            g.db = self.connect()
        return g.db


class QueryBuilder(Base):

    def __init__(self, app=None):
        self.app = None
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        backend = get_backend(app)
        cls = load_backend(backend)

        self.__class__.alerts = type('AlertsQueryBuilder', (cls.Alerts, self.Alerts, QueryBuilder), {})
        self.__class__.blackouts = type('BlackoutsQueryBuilder', (cls.Blackouts, self.Blackouts, QueryBuilder), {})
        self.__class__.heartbeats = type('HeartbeatsQueryBuilder', (cls.Heartbeats, self.Heartbeats, QueryBuilder), {})
        self.__class__.keys = type('ApiKeysQueryBuilder', (cls.ApiKeys, self.ApiKeys, QueryBuilder), {})
        self.__class__.users = type('UsersQueryBuilder', (cls.Users, self.Users, QueryBuilder), {})
        self.__class__.groups = type('GroupsQueryBuilder', (cls.Groups, self.Groups, QueryBuilder), {})
        self.__class__.perms = type('PermissionsQueryBuilder', (cls.Permissions, self.Permissions, QueryBuilder), {})
        self.__class__.customers = type('CustomersQueryBuilder', (cls.Customers, self.Customers, QueryBuilder), {})

    class Alerts:

        @staticmethod
        def from_params(params, customers=None, query_time=None):
            raise NotImplementedError('AlertsQueryBuilder has no from_params() method for alerts')
