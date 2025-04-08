from flask import (Blueprint, request,g)
import logging

from privacyidea.api.auth import admin_required
from privacyidea.lib.error import ParameterError
from privacyidea.api.lib.utils import required,send_result,getParam
from privacyidea.models import ServiceRiskScore,UserTypeRiskScore,IPRiskScore
from privacyidea.lib.config import get_from_config, get_token_types,set_privacyidea_config
from privacyidea.lib.riskbase import LDAP_GROUP_RESOLVER_NAME_STR,LDAP_USER_GROUP_DN_STR,LDAP_USER_GROUP_SEARCH_ATTR_STR, sanitize_risk_score,ip_version,get_user_groups,calculate_risk,get_groups

log = logging.getLogger(__name__) 

riskbase_blueprint = Blueprint('riskbase_blueprint', __name__)

@riskbase_blueprint.route("/",methods=["GET"])
@admin_required
def get_risk_config():
    """
    """
    users = UserTypeRiskScore.query.all()
    services = ServiceRiskScore.query.all()
    ips = IPRiskScore.query.all()

    r = {}
    
    r["user_types"] = get_groups()
    r["token_types"] = get_token_types()
    
    resolver = get_from_config(LDAP_GROUP_RESOLVER_NAME_STR)
    if resolver:
        r["groupResolver"] = resolver
        
    userGroupDN = get_from_config(LDAP_USER_GROUP_DN_STR)
    if userGroupDN:
        r["userGroupDN"] = userGroupDN
        
    userGroupAttr = get_from_config(LDAP_USER_GROUP_SEARCH_ATTR_STR)
    if userGroupAttr:
        r["userGroupAttr"] = userGroupAttr
    
    if len(users) > 0:
        r["user_risk"] = [{"id": entry.id,"type": entry.user_type, "risk_score": entry.risk_score} for entry in users]
    
    if len(services) > 0:
        r["service_risk"] = [{"id": entry.id,"name": entry.service_name, "risk_score": entry.risk_score} for entry in services]
    
    if len(ips) > 0 :
        r["ip_risk"] = [{"id": entry.id,"ip": f"{entry.ip}/{entry.mask}", "risk_score": entry.risk_score} for entry in ips]
     
    return send_result(r)

@riskbase_blueprint.route("/groups",methods=["POST"])
@admin_required
def group_connection_config():
    params = request.all_data
    resolver_name = getParam(params,"resolver_name",required,allow_empty=False)
    user_to_group_search_attr = getParam(params,"user_to_group_search_attr",allow_empty=False)
    user_to_group_base_dn = getParam(params,"user_to_group_dn",allow_empty=False)
    
    parameters = {LDAP_GROUP_RESOLVER_NAME_STR: resolver_name,
                  LDAP_USER_GROUP_SEARCH_ATTR_STR: user_to_group_search_attr,
                  LDAP_USER_GROUP_DN_STR: user_to_group_base_dn}
    
    for key,value in parameters.items():
        set_privacyidea_config(key,value)
        
    return send_result(True)

@riskbase_blueprint.route("/groups/test",methods=["POST"])
# @admin_required
def test_fetch_user_group():
    params = request.all_data
    resolver_name = getParam(params,"resolver_name",required,allow_empty=False)
    user_dn = getParam(params,"user_dn",allow_empty=False)
    base_dn = getParam(params,"user_to_group_dn",allow_empty=False)
    attr = getParam(params,"user_to_group_search_attr",allow_empty=False)
    
    try:
        groups = get_user_groups(user_dn,resolver_name,base_dn,attr)
        desc = f"Fetched {len(groups)} group(s). Check the browser console for a full list."
    except:
        desc = "Test failed. Check privacyIDEA's logs for more info."
    
    return send_result(groups,details={"description": desc})
    
    
@riskbase_blueprint.route("/check",methods=["POST"])
@admin_required
def check():
    params = request.all_data
    userType = getParam(params,"user")
    service = getParam(params,"service")
    ip = getParam(params,"ip")
    
    r = calculate_risk(ip,service,userType)
    
    return send_result(r)


    
@riskbase_blueprint.route("/user",methods=["POST"])
@admin_required
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
@admin_required
def set_service_risk():
    """
    """
    param = request.all_data
    service = getParam(param,"service",required)
    score = getParam(param,"risk_score",required)
    
    score = sanitize_risk_score(score)
    
    r = ServiceRiskScore(service,score).save()
    
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

@riskbase_blueprint.route("/user/<identifier>",methods=["DELETE"])
@admin_required
def delete_user_risk(identifier):
    identifier = int(identifier)
    
    ur = UserTypeRiskScore.query.filter_by(id=identifier).first()
    
    if ur == None:
        raise ParameterError("User risk with the specified identifier does not exist.")
    
    r = ur.delete()
    
    return send_result(r)

@riskbase_blueprint.route("/service/<identifier>",methods=["DELETE"])
@admin_required
def delete_service_risk(identifier):
    identifier = int(identifier)
    
    sr = ServiceRiskScore.query.filter_by(id=identifier).first()
    
    if sr == None:
        raise ParameterError("Service risk with the specified identifier does not exist.")
    
    r = sr.delete()
    
    return send_result(r)

@riskbase_blueprint.route("/ip/<identifier>",methods=["DELETE"])
@admin_required
def delete_ip_risk(identifier):
    identifier = int(identifier)
    
    ip = IPRiskScore.query.filter_by(id=identifier).first()
    
    if ip == None:
        raise ParameterError("IP risk with the specified identifier does not exist.")
    
    r = ip.delete()

    return send_result(r)