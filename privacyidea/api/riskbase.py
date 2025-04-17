from flask import (Blueprint, request,g)
import logging

from privacyidea.api.auth import admin_required
from privacyidea.lib.error import ParameterError
from privacyidea.api.lib.utils import required,send_result,getParam
from privacyidea.lib.config import get_from_config, get_token_types,set_privacyidea_config
from privacyidea.lib.riskbase import LDAP_GROUP_RESOLVER_NAME_STR,LDAP_USER_GROUP_DN_STR,LDAP_USER_GROUP_SEARCH_ATTR_STR,CONFIG_GROUPS_RISK_SCORES_KEY,CONFIG_IP_RISK_SCORES_KEY,CONFIG_SERVICES_RISK_SCORES_KEY,ip_version,get_user_groups,calculate_risk,get_groups,get_risk_scores,save_risk_score,remove_risk_score

log = logging.getLogger(__name__) 

riskbase_blueprint = Blueprint('riskbase_blueprint', __name__)

@riskbase_blueprint.route("/",methods=["GET"])
@admin_required
def get_risk_config():
    """
    Retrieves all information related to the risk-base page:
    
    user_groups - all groups of users
    
    token_types- all token types that privacyIDEA has
    
    group_resolver - the base ldap resolver that is used to search for user groups
    
    user_group_dn - the base LDAP DN that is used to search the group that a user belongs to
    
    user_group_attr - The name of the LDAP attribute that, along with the user DN, is used to fetch the groups 
    the user belongs to. Used in the search filter.
    
    user_risk - the user types and their defined risk scores
    
    service_risk - the services and their defined risk scores
    
    ip_risk - the ips and their defined risk scores 
    """
    users = get_risk_scores(CONFIG_GROUPS_RISK_SCORES_KEY)
    services = get_risk_scores(CONFIG_SERVICES_RISK_SCORES_KEY)
    ips = get_risk_scores(CONFIG_IP_RISK_SCORES_KEY)

    r = {}
    
    r["user_groups"] = get_groups()
    r["token_types"] = get_token_types()
    
    resolver = get_from_config(LDAP_GROUP_RESOLVER_NAME_STR)
    if resolver:
        r["group_resolver"] = resolver
        
    userGroupDN = get_from_config(LDAP_USER_GROUP_DN_STR)
    if userGroupDN:
        r["user_group_dn"] = userGroupDN
        
    userGroupAttr = get_from_config(LDAP_USER_GROUP_SEARCH_ATTR_STR)
    if userGroupAttr:
        r["user_group_attr"] = userGroupAttr
    
    if len(users) > 0:
        r["user_risk"] = [{"group": entry[0], "risk_score": entry[1]} for entry in users]
    
    if len(services) > 0:
        r["service_risk"] = [{"name": entry[0], "risk_score": entry[1]} for entry in services]
    
    if len(ips) > 0 :
        r["ip_risk"] = [{"ip": entry[0], "risk_score": entry[1]} for entry in ips]
     
    return send_result(r)

@riskbase_blueprint.route("/groups",methods=["POST"])
@admin_required
def group_connection_config():
    """
    Sets the config parameters for the group search
    
    :jsonparam resolver_name: The name of the base LDAP resolver to be used
    :jsonparam user_to_group_search_attr: The name of the LDAP attribute that, along with the user DN, is used to fetch the groups 
    the user belongs to. Used in the search filter.
    :jsonparam user_to_group_dn: The base LDAP DN to use when searching for the group that a user belongs to
    """
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
@admin_required
def test_fetch_user_group():
    """
    Tests the group search configuration.
    
    Parameters are the same as the /groups endpoint.
    
    :jsonparam user_dn: LDAP DN of a user to test the group search.
    
    :return: JSON with the groups found.
    """
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
    """
    Calculates the risk score based on the provided user, service and IP.
    
    Used for testing the configuration.
    
    :jsonparam user: the user group that is used to calculate the risk for the test
    :jsonparam service: the service that is used to calculate the risk for the test
    :jsonparam ip: the IP that is used to calculate the risk for the test
    
    :return: JSON with risk score calculated
    """
    params = request.all_data
    userType = getParam(params,"user")
    service = getParam(params,"service")
    ip = getParam(params,"ip")
    
    r = calculate_risk(ip,service,[userType])
    
    return send_result(r)


    
@riskbase_blueprint.route("/user",methods=["POST"])
@admin_required
def set_user_risk():
    """
    Sets the risk score for a group of users
    
    :jsonparam user_group: the group to which the risk score will be attached
    :jsonparam risk_score: the risk score for the user group
    """
    
    param = request.all_data
    user_group = getParam(param,"user_group",required)
    score = getParam(param,"risk_score",required)
    
    save_risk_score(user_group,score,CONFIG_GROUPS_RISK_SCORES_KEY)
    
    return send_result(True)
    

@riskbase_blueprint.route("/service",methods=["POST"])
@admin_required
def set_service_risk():
    """
    Sets the risk score for a service
    
    :jsonparam service: the service to which the risk score will be attached
    :jsonparam risk_score: the risk score for the service
    """
    param = request.all_data
    service = getParam(param,"service",required)
    score = getParam(param,"risk_score",required)
    
    save_risk_score(service,score,CONFIG_SERVICES_RISK_SCORES_KEY)
    
    return send_result(True)

@riskbase_blueprint.route("/ip",methods=["POST"])
@admin_required
def set_ip_risk():
    """
    Set the risk score for an IP or subnet
    
    :jsonparam ip: the ip or subnet address
    :jsonparam riskscore: the risk score for the subnet or IP
    """
    param = request.all_data
    ip: str = getParam(param,"ip",required,allow_empty=False)
    risk_score = getParam(param,"risk_score",required,allow_empty=False)
    
    version = ip_version(ip)
    
    if version == 0:
        raise ParameterError("Invalid IP address or network")

    tmp = ip.split("/")
    mask = None
    if len(tmp) > 1:
        mask = int(tmp[1])
        ip = tmp[0]
    
    if not mask:
        mask = 32 if version == 4 else 128
        
    ip = f"{ip}/{mask}"
    save_risk_score(ip,risk_score,CONFIG_IP_RISK_SCORES_KEY)

    return send_result(True)

@riskbase_blueprint.route("/user/delete",methods=["POST"])
@admin_required
def delete_user_risk():
    """
    Deletes the risk score attached to the user group
    
    :jsonparam identifier: the name of the group
    """
    param = request.all_data
    identifier = getParam(param,"identifier")
    
    remove_risk_score(identifier,CONFIG_GROUPS_RISK_SCORES_KEY)
    
    return send_result(True)

@riskbase_blueprint.route("/service/delete",methods=["POST"])
@admin_required
def delete_service_risk():
    """
    Deletes the risk score attached to the service
    
    :jsonparam identifier: the name of the service
    """
    param = request.all_data
    identifier = getParam(param,"identifier")
    
    remove_risk_score(identifier,CONFIG_SERVICES_RISK_SCORES_KEY)
    
    return send_result(True)

@riskbase_blueprint.route("/ip/delete",methods=["POST"])
@admin_required
def delete_ip_risk():
    """
    Deletes the risk score attached to the IP or subnet
    
    :jsonparam identifier: the IP or subnet
    """
    param = request.all_data
    identifier = getParam(param,"identifier")
    
    remove_risk_score(identifier,CONFIG_IP_RISK_SCORES_KEY)
    
    return send_result(True)