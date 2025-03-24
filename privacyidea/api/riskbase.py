from flask import (Blueprint, request,g)
import logging

from privacyidea.api.auth import admin_required
from privacyidea.lib.error import ParameterError
from privacyidea.api.lib.utils import required,optional,send_result,getParam
from privacyidea.lib.user import User, get_user_from_param
from privacyidea.models import ServiceRiskScore,UserTypeRiskScore,IPRiskScore,ThresholdScore
from privacyidea.lib.config import get_token_types
from privacyidea.lib.riskbase import get_ip_risk_score,get_service_risk_score,get_user_risk_score,sanitize_risk_score,ip_version

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
        ip_risk_score = get_ip_risk_score(ip)
        
    if service != None:
        service_risk_score = get_service_risk_score(service)
        
    user_risk_score = get_user_risk_score(user_obj)
    
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
        "user_risk": [
            {"id": 0,"type": "Professor", "risk_score": 5},
            {"id": 1,"type": "Admin", "risk_score": 10}
        ], 
        "service_risk": [
            {"id": 0,"name": "servico 1", "risk_score": 2},
            {"id": 1,"name": "paco", "risk_score": 5},
            {"id": 2,"name": "elearning", "risk_score": 1}
        ],
        "ip_risk": [
            {"id": 0,"ip": "192.168.5.0/24", "risk_score": 3}
        ],
        "thresholds": [
            {"id": 0,"token": "TOTP", "threshold": 7},
            {"id": 1,"token": "PUSH", "threshold": 5}
        ]
    }

@riskbase_blueprint.route("/",methods=["GET"])
def get_risk_config():
    """
    """
    users = UserTypeRiskScore.query.all()
    services = ServiceRiskScore.query.all()
    ips = IPRiskScore.query.all()
    trs = ThresholdScore.query.all()

    r = {}
    
    r["default_user_risk"] = 3
    r["default_service_risk"] = 7
    r["default_ip_risk"] = 5
    r["user_types"] = ["Student", "Admin", "Professor"]
    r["token_types"] = get_token_types()
    
    if len(users) > 0:
        r["user_risk"] = []
        for entry in users:
            r["user_risk"].append({"id": entry.id,"type": entry.user_type, "risk_score": entry.risk_score})
    
    if len(services) > 0:
        r["service_risk"] = []
        for entry in services:
            r["service_risk"].append({"id": entry.id,"name": entry.service_name, "risk_score": entry.risk_score})
    
    if len(ips) > 0 :
        r["ip_risk"] = []
        for entry in ips:
            r["ip_risk"].append({"id": entry.id,"ip": f"{entry.ip}/{entry.mask}", "risk_score": entry.risk_score})
    
    if len(trs) > 0:
        r["thresholds"] = []
        for entry in trs:
            r["thresholds"].append({"id": entry.id,"token": entry.token,"threshold": entry.threshold})
    
    return send_result(r)

@riskbase_blueprint.route("/user/<identifier>",methods=["DELETE"])
def delete_user_risk(identifier):
    identifier = int(identifier)
    
    ur = UserTypeRiskScore.query.filter_by(id=identifier).first()
    
    if ur == None:
        raise ParameterError("User risk with the specified identifier does not exist.")
    
    r = ur.delete()
    
    return send_result(r)

@riskbase_blueprint.route("/service/<identifier>",methods=["DELETE"])
def delete_service_risk(identifier):
    identifier = int(identifier)
    
    sr = ServiceRiskScore.query.filter_by(id=identifier).first()
    
    if sr == None:
        raise ParameterError("Service risk with the specified identifier does not exist.")
    
    r = sr.delete()
    
    return send_result(r)

@riskbase_blueprint.route("/ip/<identifier>",methods=["DELETE"])
def delete_ip_risk(identifier):
    identifier = int(identifier)
    
    ip = IPRiskScore.query.filter_by(id=identifier).first()
    
    if ip == None:
        raise ParameterError("IP risk with the specified identifier does not exist.")
    
    r = ip.delete()

    return send_result(r)

@riskbase_blueprint.route("/threshold/<identifier>",methods=["DELETE"])
def delete_threshold(identifier):
    identifier = int(identifier)

    ts = ThresholdScore.query.filter_by(id=identifier).first()
    
    if ts == None:
        raise ParameterError("Threshold with the specified identifier does not exist.")
    
    r = ts.delete()
    
    return send_result(r)
    
@riskbase_blueprint.route("/user",methods=["POST"])
def set_user_risk():
    """
    """
    
    param = request.all_data
    user_type = getParam(param,"user_type",required)
    score = getParam(param,"risk_score",required)
    
    score = sanitize_risk_score(score)
    
    #TODO: check if type exists
    r = UserTypeRiskScore(user_type,score).save()
    
    return send_result(r)
    

@riskbase_blueprint.route("/service",methods=["POST"])
def set_service_risk():
    """
    """
    param = request.all_data
    service = getParam(param,"service",required)
    score = getParam(param,"risk_score",required)
    
    score = sanitize_risk_score(score)
    
    r = ServiceRiskScore(service,score).save()
    
    return send_result(r)

@riskbase_blueprint.route("/threshold",methods=["POST"])
def set_threshold():
    param = request.all_data
    token_type = getParam(param,"token",required)
    threshold = getParam(param,"threshold",required)
    
    #TODO: check if token_type exists
    if not token_type in get_token_types():
        raise ParameterError("Token type does not exist.")
        
    r = ThresholdScore(token_type,threshold).save()
    
    return send_result(r)

@riskbase_blueprint.route("/ip",methods=["POST"])
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
    
    version = ip_version(ip)
    
    tmp = ip.split("/")
    mask = None
    if len(tmp) > 1:
        try:
            mask = int(tmp[1])
            ip = tmp[0]
        except:
            raise ParameterError("IP mask must be an integer.")
    
    if version == 0:
        raise ParameterError("Invalid {0!s}".format("IP address" if mask is None else "subnet"))

    risk_score = sanitize_risk_score(risk_score)
    
    if mask is None:
        mask = 32 if version == 4 else 128
        
    r = IPRiskScore(ip,mask=mask,risk_score=risk_score).save()
    
    return send_result(r)

    