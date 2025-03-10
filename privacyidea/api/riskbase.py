from flask import (Blueprint, request,g)
import logging

from privacyidea.api.auth import admin_required
from privacyidea.lib.error import ParameterError
from privacyidea.lib.log import log_with
from privacyidea.api.lib.utils import required,optional,send_result,getParam
from privacyidea.lib.user import User, get_user_from_param
from privacyidea.models import ServiceRiskScore,UserTypeRiskScore,IPRiskScore
import ipaddress

log = logging.getLogger(__name__)

riskbase_blueprint = Blueprint('riskbase_blueprint', __name__)

@riskbase_blueprint.route('', methods=['POST'])
def check_risk():
    """
    Checks if a user requires two factor authentication or not (risk based authn)
    
    :queryparam user: username of the user
    :queryparam realm: the realm of the user
    :queryparam ip: ip of the request
    :queryparam servicename: name of the service the user is trying to access
    :return: JSON with value=True if MFA is required or value=False otherwise
    """
    
    param = request.all_data
    user_obj: User = get_user_from_param(param,required)
    ip = getParam(param,"ip",optional,allow_empty=False)
    service = getParam(param,"servicename",optional,allow_empty=False)
    
    #TODO: use the default risk score
    service_risk_score = -1
    ip_risk_score = -1
    
    if ip != None:
        ip_risk_score = _get_ip_risk_score(ip)
        
    if service != None:
        service_risk_score = _get_service_risk_score(service)
        
    user_risk_score = _get_user_risk_score(user_obj)
    
    #check if any of the risk scores are "blocked"
    if ip_risk_score == -1 or service_risk_score == -1 or user_risk_score == -1:
        return send_result(True)
    
    THRESHOLD = 10
    
    r = True
    if user_risk_score + service_risk_score + ip_risk_score < THRESHOLD:
        r = False
        
    return send_result(r)

x = {
        "default_user_risk": 3,
        "default_service_risk": 7,
        "default_ip_risk": 5,
        "user_types": ["Student", "Admin", "Professor"],
        "user_risk": {
            "Professor": 5,
            "Admin": 10 
        },
        "service_risk": {
            "servico 1": 2,
            "paco": 5,
            "elearning": 1
        },
        "ip_risk": {
            "192.168.5.0/24": 3
        }
    }

@riskbase_blueprint.route("/",methods=["GET"])
@admin_required
def get_risk_config():
    """
    """
    
    return send_result(x)

@riskbase_blueprint.route("/user/<identifier>",methods=["DELETE"])
@admin_required
def delete_user_risk(identifier):
    if not identifier in x["user_risk"]:
        raise ParameterError("Identifier does not exist.")
    
    del x["user_risk"][identifier]

@riskbase_blueprint.route("/service/<identifier>",methods=["DELETE"])
@admin_required
def delete_service_risk(identifier):
    if not identifier in x["service_risk"]:
        raise ParameterError("Identifier does not exist.")
    
    del x["serivce_risk"][identifier]

@riskbase_blueprint.route("/ip/<identifier>",methods=["DELETE"])
@admin_required
def delete_ip_risk(identifier):
    if not identifier in x["ip_risk"]:
        raise ParameterError("Identifier does not exits.")
    
    del x["ip_risk"][identifier]
    
@riskbase_blueprint.route("/user",methods=["POST"])
@admin_required
def set_user_risk():
    """
    """
    
    param = request.all_data
    user_type = getParam(param,"user_type",required)
    score = getParam(param,"risk_score",required)
    
    score = sanitize_risk_score(score)
    
    x["user_risk"][user_type] = score
    
    r = True
    
    return send_result(r)
    

@riskbase_blueprint.route("/service",methods=["POST"])
@admin_required
def set_service_risk():
    """
    """
    param = request.all_data
    service = getParam(param,"service",required)
    score = getParam(param,"risk_score",required)
    
    score = sanitize_risk_score(score)
    
    x["service_risk"][service] = score
    
    r = True
    
    return send_result(r)


@riskbase_blueprint.route("/ip",methods=["POST"])
@admin_required
def set_ip_risk():
    """
    Set the risk score for an IP or subnet
    
    :queryparam ip: the ip address
    :queryparam riskscore: the risk score to be attached to the IP
    :return:
    """
    param = request.all_data
    ip: str = getParam(param,"ip",required,allow_empty=False)
    risk_score = getParam(param,"risk_score",required,allow_empty=False)
    
    risk_score = sanitize_risk_score(risk_score)
    
    x["ip_risk"][ip] = risk_score
    r = True
    # version = ip_version(ip)
    
    # tmp = ip.split("/")
    # mask = None
    # if len(tmp) > 1:
    #     try:
    #         mask = int(tmp[1])
    #     except:
    #         raise ParameterError("IP mask must be an integer.")
    
    # if version == 0:
    #     raise ParameterError("Invalid {0!s}".format("IP address" if mask is None else "subnet"))

    # risk_score = sanitize_risk_score(risk_score)
    
    # if mask is None:
    #     mask = 32 if version == 4 else 128
        
    # r = IPRiskScore(ip,mask=mask,risk_score=risk_score).save()
    
    return send_result(r)
    
def _get_ip_risk_score(ip):
    addr = ipaddress.ip_address(ip)
    version = ip_version(ip)
    ip_type = IPRiskScore.PUBLIC if addr.is_global else IPRiskScore.PRIVATE
    subnets = IPRiskScore.query.filter_by(ip_version=version,ip_type=ip_type).all()

    #TODO: use the default ip risk score if the query is empty
    if subnets == None:
        return 0
    
    #get all subnets that hold the ip
    subnets = [create_subnet(subnet.ip,subnet.mask) for subnet in subnets]
    subnets = [subn for subn in subnets if matches_subnet(ip,subn)]

    if len(subnets) == 0:
        #TODO: use the default ip risk score
        return 0
    
    subnet_highest_mask = get_subnet_with_highest_mask(subnets)
    #fetch the risk score for the subnet
    ip_risk_score = IPRiskScore.query.filter_by(ip=str(subnet_highest_mask.network_address),mask=subnet_highest_mask.prefixlen).first().risk_score
    return ip_risk_score

def _get_service_risk_score(service):
    service_query = ServiceRiskScore.query.filter_by(service_name=service).first()
        
    #TODO: use the default service risk score if the query is empty
    if service_query == None:
        return 0
    
    service_risk_score = service_query.risk_score
    return service_risk_score

def _get_user_risk_score(user: User):
    user_risk_score = user.attributes.get("risk_score",None)
    if user_risk_score == None:
        type_query = UserTypeRiskScore.query.filter_by(user_type=user.info.get("type",None)).first()
        
        #TODO: use the default user risk score if the query is empty
        if type_query == None:
            return 0
        
        user_risk_score = type_query.risk_score
        
    return user_risk_score
       


@log_with(log)
def sanitize_risk_score(risk_score):
    """Sanitizes the risk score. Checks if it's a number.

    Args:
        risk_score (Any): the risk score to be sanitized

    Raises:
        ParameterError: if risk score is not a number

    Returns:
        float: the sanitized risk score.
    """
    try:
        risk_score = float(risk_score)
    except:
        log.info("invalid risk score: %s",risk_score)
        raise ParameterError("Risk score must be a number")
    
    if risk_score < 0:
        raise ParameterError("Risk score must be a positive number")
    
    return risk_score

def ip_version(subnet):
    try:
        ipaddress.IPv4Network(subnet)
        return 4
    except:    
        try:
            ipaddress.IPv6Network(subnet)
            return 6
        except:
            return 0
    
def ip_to_int(ip):
    return int(ipaddress.ip_address(ip))

def create_subnet(ip,mask):
    return ipaddress.ip_network(f"{ip}/{mask}")

def matches_subnet(ip, subnet):
    ip_int = ip_to_int(ip)
    network_int = ip_to_int(subnet.network_address)
    netmask_int = ip_to_int(subnet.netmask)
    
    # Apply bitwise AND to the IP and the subnet mask, then compare to the network address
    return (ip_int & netmask_int) == (network_int & netmask_int)

def get_subnet_with_highest_mask(subnets):
    return max(subnets,key=lambda subnet: ip_to_int(subnet.network_address))
    