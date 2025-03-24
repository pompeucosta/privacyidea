import ipaddress
from privacyidea.lib.error import ParameterError
from privacyidea.models import ServiceRiskScore, IPRiskScore,UserTypeRiskScore
from privacyidea.lib.user import User

def calculate_risk(ip,service,user_obj):
    ip_risk_score = get_ip_risk_score(ip)
    service_risk_score = get_service_risk_score(service)
    user_risk_score = get_user_risk_score(user_obj)

    return user_risk_score + service_risk_score + ip_risk_score    

def get_ip_risk_score(ip):
    default = 1
    
    if not ip:
        return default
    
    addr = ipaddress.ip_address(ip)
    version = ip_version(ip)
    ip_type = IPRiskScore.PUBLIC if addr.is_global else IPRiskScore.PRIVATE
    subnets = IPRiskScore.query.filter_by(ip_version=version,ip_type=ip_type).all()

    #TODO: use the default ip risk score if the query is empty
    if subnets == None:
        return default
    
    #get all subnets that hold the ip
    subnets = [create_subnet(subnet.ip,subnet.mask) for subnet in subnets]
    subnets = [subn for subn in subnets if matches_subnet(ip,subn)]

    if len(subnets) == 0:
        #TODO: use the default ip risk score
        return default
    
    subnet_highest_mask = get_subnet_with_highest_mask(subnets)
    #fetch the risk score for the subnet
    ip_risk_score = IPRiskScore.query.filter_by(ip=str(subnet_highest_mask.network_address),mask=subnet_highest_mask.prefixlen).first().risk_score
    return ip_risk_score

def get_service_risk_score(service):
    default = 1
    if not service:
        return default
    
    service_query = ServiceRiskScore.query.filter_by(service_name=service).first()
        
    #TODO: use the default service risk score if the query is empty
    if service_query == None:
        return default
    
    service_risk_score = service_query.risk_score
    return service_risk_score

def get_user_risk_score(user: User):
    default = 1
    
    if not user:
        return default
    
    type_query = UserTypeRiskScore.query.filter_by(user_type=user.info.get("type",None)).first()
        
    #TODO: use the default user risk score if the query is empty
    if type_query == None:
        return default
        
    user_risk_score = type_query.risk_score
        
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
