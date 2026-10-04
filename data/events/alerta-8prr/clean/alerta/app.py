from typing import Any, Dict

import sentry_sdk
from flask import Flask
from flask_compress import Compress
from flask_cors import CORS
from sentry_sdk.integrations.flask import FlaskIntegration
from werkzeug.middleware.proxy_fix import ProxyFix

from alerta.database.base import Database, QueryBuilder
from alerta.exceptions import ExceptionHandlers
from alerta.models.alarms import AlarmModel
from alerta.models.enums import Scope
from alerta.utils.audit import AuditTrail
from alerta.utils.config import Config
from alerta.utils.hooks import HookTrigger
from alerta.utils.key import ApiKeyHelper
from alerta.utils.logging import Logger
from alerta.utils.mailer import Mailer
from alerta.utils.plugin import Plugins
from alerta.utils.tracing import Tracing
from alerta.utils.webhook import CustomWebhooks
from alerta.version import __version__

alarm_model = AlarmModel()

db = Database()
qb = QueryBuilder()

try:
    from celery import Celery
except ImportError:
    pass
