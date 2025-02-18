from flask import (Blueprint, request,g)
import logging

from privacyidea.api.lib.prepolicy import check_anonymous_user, prepolicy
from privacyidea.lib.log import log_with
from privacyidea.api.lib.utils import required,send_result
from privacyidea.lib.user import get_user_from_param
from datetime import datetime
from dateutil.relativedelta import relativedelta

log = logging.getLogger(__name__)

riskbase_blueprint = Blueprint('riskbase_blueprint', __name__)

@riskbase_blueprint.route('', methods=['POST'])
@log_with(log)
def check_risk():
    """
    This method checks if a user requires two factor authentication or not (risk based authn)
    :queryparam user: username of the user
    :return: JSON with value=True or value=False
    """
    NOW = datetime.now()
    MAX_TIMESPAN = NOW - relativedelta(days=30)
    param = request.all_data
    user_obj = get_user_from_param(param,required)
    user_ip = g.client_ip
    
    r = True
    ip_last_used_date = user_obj.attributes.get(user_ip,None)

    if ip_last_used_date:
        date = datetime.strptime(ip_last_used_date,"%x")
        r = MAX_TIMESPAN > date
    
    return send_result(r)

    
    