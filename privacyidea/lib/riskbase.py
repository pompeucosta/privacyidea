import ipaddress
import logging
from privacyidea.lib.error import ParameterError
from privacyidea.lib.resolver import get_resolver_object
from privacyidea.lib.resolvers.LDAPIdResolver import IdResolver
from privacyidea.models import ServiceRiskScore, IPRiskScore,UserTypeRiskScore
from privacyidea.lib.config import get_from_config

DEFAULT_USER_RISK = 3
DEFAULT_IP_RISK = 1
DEFAULT_SERVICE_RISK = 5

LDAP_USER_GROUP_DN_STR = "ldap_user_group_base_dn"
LDAP_USER_GROUP_SEARCH_ATTR_STR = "ldap_user_group_search_attr"
LDAP_GROUP_RESOLVER_NAME_STR = "resolver_name"


log = logging.getLogger(__name__) 

def calculate_risk(ip: str,service: str,user_type: list):
    ip_risk_score = get_ip_risk_score(ip)
    service_risk_score = get_service_risk_score(service)
    user_risk_score = get_user_risk_score(user_type)

    return user_risk_score + service_risk_score + ip_risk_score    

def get_groups():
    resolver = _get_group_resolver()
    if not resolver:
        return []
    
    _groups = resolver.getUserList({})
    groups = set()
    
    for entry in _groups:
        groups.add(entry["username"])
    
    return list(groups)

def get_user_groups(user_dn,resolver_name=None,dn=None,attr=None):
    resolver = _get_group_resolver(resolver_name)
    if not resolver:
        return []

    base = dn or get_from_config(LDAP_USER_GROUP_DN_STR) or resolver.basedn
    search_attr = attr or get_from_config(LDAP_USER_GROUP_SEARCH_ATTR_STR) or "member"
    search_filter = f"({search_attr}={user_dn})"
    entries = resolver._search(base,search_filter,resolver.loginname_attribute)
    
    if len(entries) == 0:
        log.debug(f"Found 0 entries for group search. Base: {base}. Attr: {search_attr}. Filter: {search_filter}")
        return []
    
    groups = set()
    for entry in entries:
        attrs = entry.get("attributes", {})
        for loginname in resolver.loginname_attribute:
            name = attrs.get(loginname,"")
            if name:
                groups.update(name)
    
    log.debug(f"Found groups: {list(groups)}")
    return list(groups)

def _get_group_resolver(resolver_name=None):
    rname = resolver_name or get_from_config(LDAP_GROUP_RESOLVER_NAME_STR)
    if not rname:
        log.info("Name for group resolver not set. User group can not be fetched.")
        return None
    
    resolver: IdResolver = get_resolver_object(rname)
    
    if not resolver:
        log.error("Can not find resolver with name {0!s}!",rname)
        
    return resolver

def get_ip_risk_score(ip: str):
    default = get_from_config("DefaultIPRiskScore") or DEFAULT_IP_RISK
    
    if not ip:
        return default
    
    addr = ipaddress.ip_address(ip)
    version = ip_version(ip)
    ip_type = IPRiskScore.PUBLIC if addr.is_global else IPRiskScore.PRIVATE
    subnets = IPRiskScore.query.filter_by(ip_version=version,ip_type=ip_type).all()

    if subnets == None:
        return default
    
    #get all subnets that hold the ip
    subnets = [create_subnet(subnet.ip,subnet.mask) for subnet in subnets]
    subnets = [subn for subn in subnets if matches_subnet(ip,subn)]

    if len(subnets) == 0:
        return default
    
    subnet_highest_mask = get_subnet_with_highest_mask(subnets)
    #fetch the risk score for the subnet
    ip_risk_score = IPRiskScore.query.filter_by(ip=str(subnet_highest_mask.network_address),mask=subnet_highest_mask.prefixlen).first().risk_score
    return ip_risk_score

def get_service_risk_score(service: str):
    default = get_from_config("DefaultServiceRiskScore") or DEFAULT_SERVICE_RISK 
    
    if not service:
        return default
    
    service_query = ServiceRiskScore.query.filter_by(service_name=service).first()
        
    if service_query == None:
        return default
    
    service_risk_score = service_query.risk_score
    return service_risk_score

def get_user_risk_score(utype: list):
    default = get_from_config("DefaultUserRiskScore") or DEFAULT_USER_RISK
    
    if not utype:
        return default
    
    types = []
    for t in utype:
        tmp = UserTypeRiskScore.query.filter_by(user_type=t).first()
        if tmp:
            types.append((t,tmp.risk_score)) 
            
    if len(types) == 0:
        log.debug(f"No risk scores found for groups {utype}")
        return default
        
    scores = sorted(types,key=lambda tp: tp[1])
    log.debug(f"Scores: {scores}")
    
    log.debug(f"Using score defined for type {scores[-1][0]}: {scores[-1][1]}")
    user_risk_score = scores[-1][1]
        
    return user_risk_score
       

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
    
def _ip_to_int(ip):
    return int(ipaddress.ip_address(ip))

def create_subnet(ip,mask):
    return ipaddress.ip_network(f"{ip}/{mask}")

def matches_subnet(ip, subnet):
    ip_int = _ip_to_int(ip)
    network_int = _ip_to_int(subnet.network_address)
    netmask_int = _ip_to_int(subnet.netmask)
    
    # Apply bitwise AND to the IP and the subnet mask, then compare to the network address
    return (ip_int & netmask_int) == (network_int & netmask_int)

def get_subnet_with_highest_mask(subnets):
    return max(subnets,key=lambda subnet: _ip_to_int(subnet.network_address))
