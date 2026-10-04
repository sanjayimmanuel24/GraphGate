from datetime import datetime

from flask import current_app, g, jsonify, request
from flask_cors import cross_origin

from alerta.app import qb
from alerta.auth.decorators import permission
from alerta.exceptions import (AlertaException, ApiError, BlackoutPeriod,
                               ForwardingLoop, HeartbeatReceived,
                               InvalidAction, RateLimit, RejectException)
from alerta.models.alert import Alert
from alerta.models.enums import Scope
from alerta.models.metrics import Timer, timer
from alerta.models.note import Note
from alerta.models.switch import Switch
from alerta.utils.api import (assign_customer, process_action, process_alert,
                              process_delete, process_note, process_status)
from alerta.utils.audit import write_audit_trail
from alerta.utils.paging import Page
from alerta.utils.response import absolute_url, jsonp

from . import api

count_timer = Timer('alerts', 'counts', 'Count alerts', 'Total time and number of count queries')


# severity counts
# status counts
@api.route('/alerts/count', methods=['OPTIONS', 'GET'])
@cross_origin()
@permission(Scope.read_alerts)
@timer(count_timer)
@jsonp
def get_counts():
    query = qb.alerts.from_params(request.args, customers=g.customers)
    severity_count = Alert.get_counts_by_severity(query)
    status_count = Alert.get_counts_by_status(query)

    return jsonify(
        status='ok',
        total=sum(severity_count.values()),
        severityCounts=severity_count,
        statusCounts=status_count,
        autoRefresh=Switch.find_by_name('auto-refresh-allow').is_on
    )
