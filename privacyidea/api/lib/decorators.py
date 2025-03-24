#  License:  AGPLv3
#  contact:  http://www.privacyidea.org
#
# This code is free software; you can redistribute it and/or
# modify it under the terms of the GNU AFFERO GENERAL PUBLIC LICENSE
# License as published by the Free Software Foundation; either
# version 3 of the License, or any later version.
#
# This code is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU AFFERO GENERAL PUBLIC LICENSE for more details.
#
# You should have received a copy of the GNU Affero General Public
# License along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
"""
These are the decorators which run before processing the request and may
modify API calls e.g. by changing the flask environment.

The postAddSerialToG decorator is tested in the ValidateAPITestCase.
"""


import logging
from flask import g
import functools
from privacyidea.lib.riskbase import calculate_risk

log = logging.getLogger(__name__)


def add_serial_from_response_to_g(wrapped_function):
    """
    This decorator checks for the serial in the response and adds it to the
    flask g object.
    """
    @functools.wraps(wrapped_function)
    def function_wrapper(*args, **kwds):
        response = wrapped_function(*args, **kwds)
        if response.is_json:
            serial = response.json.get("detail", {}).get("serial")
            if serial:
                g.serial = serial
        return response

    return function_wrapper

def add_risk_to_user(request,g):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args,**kwargs):
            user = request.User
            ip = g.client_ip
            print(request.headers)
            print(ip)
            if user:
                user.info["type"] = "Admin"
                user.info["risk"] = calculate_risk(ip,None,user)
                print(user.info["risk"])

            return func(*args,**kwargs)
        return wrapper
    
    return decorator