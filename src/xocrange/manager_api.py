"""Internal Manager API client; verifies both CA and the siem server name."""
import base64
import http.client
import json
import ssl

from .errors import XocError
from .indexer import Client, Connection
from .manager_setup import STATE
from .ui_setup import private_json


class ManagerClient(Client):
    def __init__(self,engine,project,state=STATE):
        self.engine,self.project=engine,project
        self.addresses={}
        self.credentials=private_json(state/'credentials.json')
        self.context=ssl.create_default_context(cafile=str(state/'ca.pem'))

    def request(self,method,path,body=None,*,token=None,basic=None):
        headers={'Content-Type':'application/json'}
        if token:headers['Authorization']='Bearer '+token
        if basic:headers['Authorization']='Basic '+base64.b64encode((':'.join(basic)).encode()).decode()
        connection=Connection(self.address('siem'),'siem',55000,self.context)
        try:
            connection.request(method,path,None if body is None else json.dumps(body),headers)
            response=connection.getresponse();data=response.read(8*1024**2+1)
            if len(data)>8*1024**2:raise XocError('manager_response_limit','Manager response exceeded its bounded read size.')
            return response.status,json.loads(data)
        except (OSError,http.client.HTTPException,ValueError) as error:
            self.addresses.clear()
            raise XocError('manager_api_unavailable','Verified Manager API request failed.') from error
        finally:connection.close()

    def authenticate(self):
        code,data=self.request('POST','/security/user/authenticate',basic=('wazuh',self.credentials['wazuh']))
        token=data.get('data',{}).get('token')
        if code!=200 or not isinstance(token,str):raise XocError('manager_authentication','Manager authentication failed.')
        return token
