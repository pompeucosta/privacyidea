from privacyidea.lib.user import User
from .base import MyApiTestCase
from privacyidea.lib.resolver import save_resolver
from privacyidea.lib.realm import set_realm
from privacyidea.api.riskbase import _get_ip_risk_score,_get_service_risk_score,_get_user_risk_score

class APIRiskBaseTestCase(MyApiTestCase):
    parameters = {'Driver': 'sqlite',
                  'Server': '/tests/testdata/',
                  'Database': "testrisk-api.sqlite",
                  'Table': 'users',
                  'Encoding': 'utf8',
                  'Map': '{ "username": "username", \
                    "userid" : "id", \
                    "email" : "email", \
                    "surname" : "name", \
                    "givenname" : "givenname", \
                    "password" : "password", \
                    "phone": "phone", \
                    "mobile": "mobile", \
                    "type": "type"}'
                  }
    user_name = "john doe"
    realm = "sqlrealm"
    resolver = "SQL1"
    user_type = "student"
        
    def _create_user(self):
        parameters = self.parameters
        parameters["resolver"] = self.resolver
        parameters["type"] = "sqlresolver"
        
        rid = save_resolver(parameters)
        self.assertTrue(rid > 0, rid)

        (added, failed) = set_realm(self.realm, [{'name': self.resolver}])
        self.assertEqual(len(failed), 0)
        self.assertEqual(len(added), 1)
        
        user = User(self.user_name,self.realm,self.resolver)
        if user.exist():
            return
        
        with self.app.test_request_context('/user/',
                                           method='POST',
                                           data={"user": self.user_name,
                                                 "resolver": self.resolver,
                                                 "surname": "zappa",
                                                 "givenname": "frank",
                                                 "email": "f@z.com",
                                                 "phone": "12345",
                                                 "mobile": "12345",
                                                 "password": "12345",
                                                 "type": self.user_type},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            self.assertTrue(result.get("value") > 1, result.get("value"))
            
    def _get_user_attribute(self,attribute):
        with self.app.test_request_context("/user/attribute",
                                           method="GET",
                                           query_string={"user": self.user_name,
                                                 "resolver": self.resolver,
                                                 "realm": self.realm,
                                                 "key": attribute},
                                           headers={"Authorization": self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200,res)
            attr = res.json.get("result").get("value")
            self.assertTrue(attr != None and attr != "",attr)
            return attr
        
    def test_00_set_user_risk(self):
        self._create_user()
        
        #test for missing admin auth
        with self.app.test_request_context("/riskbase/userrisk",
                                      method="POST",
                                      data={"user": self.user_name,
                                            "riskscore": 10}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 401,res)
            
        #test for missing parameter risk score
        with self.app.test_request_context("/riskbase/userrisk",
                                           method="POST",
                                           data={"user": self.user_name},
                                           headers={"Authorization": self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 400,res)
            
        #test for missing parameter user
        with self.app.test_request_context("/riskbase/userrisk",
                                           method="POST",
                                           data={"riskscore": 10},
                                           headers={"Authorization": self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 400,res)
            
        #test for a non existing user
        with self.app.test_request_context("/riskbase/userrisk",
                                           method="POST",
                                           data={"user": "non-existent","riskscore": 10},
                                           headers={"Authorization": self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 400,res)
            
        #test successful user risk
        with self.app.test_request_context("/riskbase/userrisk",
                                           method="POST",
                                           data={"user": self.user_name,"riskscore": 10},
                                           headers={"Authorization": self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200,res)
            
            risk_score = self._get_user_attribute("risk_score")
            self.assertTrue(risk_score != None,risk_score)
            self.assertTrue(float(risk_score) == float(10),type(risk_score))
        
    
    def test_01_set_service_risk(self):
        service_name = "my service"
        
        #test for missing admin auth
        with self.app.test_request_context("/riskbase/servicerisk",
                                           method="POST",
                                           data={"servicename": service_name,
                                                 "riskscore": 7}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 401,res)
        
        #test for missing parameter service 
        with self.app.test_request_context("/riskbase/servicerisk",
                                           method="POST",
                                           data={"riskscore": 7},
                                           headers={"Authorization": self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 400,res)
            
        #test for missing parameter risk score
        with self.app.test_request_context("/riskbase/servicerisk",
                                           method="POST",
                                           data={"servicename": service_name},
                                           headers={"Authorization": self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 400,res)
        
        #test successful service score
        with self.app.test_request_context("/riskbase/servicerisk",
                                           method="POST",
                                           data={"servicename": service_name,
                                                 "riskscore": 7},
                                           headers={"Authorization": self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200,res)
            
            risk_score = _get_service_risk_score(service_name)
            self.assertTrue(risk_score != None,risk_score)
            self.assertTrue(float(risk_score) == float(7),risk_score)
            
        old_risk_score = _get_service_risk_score(service_name)
        self.assertTrue(float(old_risk_score) == float(7),old_risk_score)
        
        #test update risk score
        with self.app.test_request_context("/riskbase/servicerisk",
                                           method="POST",
                                           data={"servicename": service_name,
                                                 "riskscore": 20},
                                           headers={"Authorization": self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200,res)
            
            risk_score = _get_service_risk_score(service_name)
            self.assertTrue(risk_score != None,risk_score)
            self.assertTrue(float(risk_score) == float(20),risk_score)
            self.assertTrue(risk_score != old_risk_score,old_risk_score)
    
    def test_02_set_user_type_risk(self):
        #create a different user because the previous one already has a risk score, which will conflict with the user type
        #since the user's own risk score is prefered over the user type
        self.user_name = "john doe2"
        self._create_user()
        
        #test for missing admin auth
        with self.app.test_request_context("/riskbase/usertyperisk",
                                           method="POST",
                                           data={"usertype": self.user_type,
                                                 "riskscore": 5}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 401,res)
            
        #test for missing parameter risk score
        with self.app.test_request_context("/riskbase/usertyperisk",
                                           method="POST",
                                           data={"usertype": self.user_type},
                                           headers={"Authorization": self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 400,res)
            
        #test for missing parameter user type
        with self.app.test_request_context("/riskbase/usertyperisk",
                                           method="POST",
                                           data={"riskscore": 5},
                                           headers={"Authorization": self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 400,res)
            
        #test successful user type score
        with self.app.test_request_context("/riskbase/usertyperisk",
                                           method="POST",
                                           data={"usertype": self.user_type,
                                                 "riskscore": 5},
                                           headers={"Authorization": self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200,res)
            risk_score = _get_user_risk_score(User(self.user_name,self.realm,self.resolver))
            self.assertTrue(risk_score != None,risk_score)
            self.assertTrue(float(risk_score) == float(5),risk_score)
    
    def test_03_set_ip_risk(self):
        ip = "192.168.1.0"
        mask = 24
        #test for missing admin auth
        with self.app.test_request_context("/riskbase/iprisk",
                                           method="POST",
                                           data={"ip": ip,
                                                 "mask": mask,
                                                 "riskscore": 5}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 401,res)
            
        #test for missing ip
        with self.app.test_request_context("/riskbase/iprisk",
                                           method="POST",
                                           data={"mask": mask,
                                                 "riskscore": 5},
                                           headers={"Authorization": self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 400,res)
            
        #test for missing risk score
        with self.app.test_request_context("/riskbase/iprisk",
                                           method="POST",
                                           data={"ip": ip,
                                                 "mask": mask},
                                           headers={"Authorization": self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 400,res)
            
        invalid_ip = "999.999.999.0"
        #test for invalid ip
        with self.app.test_request_context("/riskbase/iprisk",
                                           method="POST",
                                           data={"ip": invalid_ip,
                                                 "mask": mask,
                                                 "riskscore": 5},
                                           headers={"Authorization": self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 400,res)
            
        #test for valid ip with missing mask (single ip instead of subnet)
        with self.app.test_request_context("/riskbase/iprisk",
                                           method="POST",
                                           data={"ip": "192.168.3.10",
                                                 "riskscore": 15},
                                           headers={"Authorization": self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200,res)
            risk_score = _get_ip_risk_score("192.168.3.10")
            self.assertTrue(risk_score == 15,risk_score)
            
        #test for valid subnet
        with self.app.test_request_context("/riskbase/iprisk",
                                           method="POST",
                                           data={"ip": ip,
                                                 "mask": mask,
                                                 "riskscore": 5},
                                           headers={"Authorization": self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200,res)
            #because the subnet is 192.168.1.0/24 then 192.168.1.3 falls within that subnet and therefore should
            #have the risk score assign to the subnet
            risk_score = _get_ip_risk_score("192.168.1.3")
            self.assertTrue(float(risk_score) == float(5),risk_score)
        