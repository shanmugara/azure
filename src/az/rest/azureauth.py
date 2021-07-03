import msal
import requests
import json
import os
import sys
import urllib3

# app_root = os.path.split(os.path.abspath(__file__))[0]
# sys.path.insert(0, app_root)
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from az.helpers import my_logger
from az.helpers.config import config

LOG_DIR = os.environ['VIRTUAL_ENV']
log = my_logger.My_logger(logdir=LOG_DIR, logfile=__name__)
liclog = my_logger.My_logger(logdir=LOG_DIR, logfile='licence.log')
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# log.basicConfig(level=log.INFO)
class AzureAd(object):

    def __init__(self, proxy=None):

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self.session = requests.Session()
        if proxy is not None:
            self.session.proxies = proxy
        retries = Retry(total=5, backoff_factor=1, status_forcelist=[502, 503, 504])
        self.session.mount("http://", HTTPAdapter(max_retries=retries))
        self.session.mount("https://", HTTPAdapter(max_retries=retries))

        self.app = msal.ClientApplication(
            config["client_id_lic"],
            authority=config["authority"],
            client_credential=config.get("client_secret_lic")
        )

        self.auth = None
        # Firstly, check the cache to see if this end user has signed in before
        accounts = self.app.get_accounts(username=config["username"])
        if accounts:
            log.info("Account(s) exists in cache, probably with token too. Let's try.")
            self.auth = self.app.acquire_token_silent(config["scope"], account=accounts[0])

        if not self.auth:
            log.info("No suitable token exists in cache. Let's get a new one from AAD.")
            # See this page for constraints of Username Password Flow.
            # https://github.com/AzureAD/microsoft-authentication-library-for-python/wiki/Username-Password-Authentication
            self.auth = self.app.acquire_token_by_username_password(
                config["username"], config["password"], scopes=config["scope_lic"])

        if "access_token" in self.auth:
            # Calling graph using the access token
            graph_data = requests.get(  # Use token to call downstream service
                config["endpoint"],
                headers={'Authorization': 'Bearer ' + self.auth['access_token']}, ).json()
            # print("Graph API call self.auth: %s" % json.dumps(graph_data, indent=2))
        else:
            log.error(self.auth.get("error"))
            log.error(self.auth.get("error_description"))
            log.error(self.auth.get("correlation_id"))  # You may need this when reporting a bug
            if 65001 in self.auth.get("error_codes", []):  # Not mean to be coded programatically, but...
                # AAD requires user consent for U/P flow
                log.error("Visit this to consent:", self.app.get_authorization_request_url(config["scope"]))

    def search_user(self, displayname):

        raw_headers = {"Authorization": "Bearer " + self.auth['access_token'],
                       "ConsistencyLevel": "eventual"}

        query_str = '?$search="displayName:{}"'.format(displayname)
        _endpoint = config["endpoint"] + query_str
        result = self.session.get(_endpoint,
                                  headers=raw_headers)
        return result.json()

    def get_ext_attr(self, displayname):
        user = self.search_user(displayname=displayname)
        oid = user['value'][0]['id']
        print(oid)
        query_str = "/{}?$select=extm7dsnjo8_adatumext".format(oid)

        raw_headers = {"Authorization": "Bearer " + self.auth['access_token']}
        _endpoint = config["endpoint"] + query_str
        result = self.session.get(_endpoint,
                                  headers=raw_headers)

        return result.json()

    def set_user_attr(self, oid, attrname, attrval):
        """
        Set standard user attributes
        :param oid:
        :param attrname:
        :param attrval:
        :return:
        """
        raw_headers = {"Authorization": "Bearer " + self.auth['access_token'], "Content-type": "application/json"}

        data = {attrname: attrval}
        data_json = json.dumps(data)
        query_str = "/{}".format(oid)
        _endpoint = config["endpoint"] + query_str

        result = self.session.patch(url=_endpoint, data=data_json, headers=raw_headers)

        return result

    def set_open_extension(self, extensionname, extattrname, extattrval, oid):
        """
        CReate and open extension for user
        :param extensionname: open extension name
        :param extattrname: extension attribute name
        :param extattrval: extension attribute value
        :return:
        """
        raw_headers = {"Authorization": "Bearer " + self.auth['access_token'], "Content-type": "application/json"}

        data = {"@odata.type": "microsoft.graph.openTypeExtension",
                "extensionName": extensionname,
                extattrname: extattrval
                }

        data_json = json.dumps(data)
        _endpoint = config["endpoint"] + "/{}/extensions".format(oid)
        result = self.session.post(url=_endpoint, data=data_json, headers=raw_headers)

        return result

    def get_open_extensions(self, oid):
        """
        Get open extensions from user
        :param oid:
        :return:
        """
        raw_headers = {"Authorization": "Bearer " + self.auth['access_token'], "Content-type": "application/json"}
        _endpoint = config["endpoint"] + "/{}/extensions".format(oid)

        try:
            result = self.session.get(url=_endpoint, headers=raw_headers)
            return result.json()

        except Exception as e:
            log.error('Exception while making REST call - {}'.format(e))
            return False

    def get_licences_o365e5(self):
        """
        Get a full licence count of E5
        :return:
        """
        guid = "009ebdb7-1526-4c4e-bdbb-4d6305d2c24e_c7df2760-2c81-4ef7-b578-5b5392b571df"
        raw_headers = {"Authorization": "Bearer " + self.auth['access_token'], "Content-type": "application/json"}
        _endpoint = config["apiurl"] + "/subscribedSkus/{}".format(guid)

        try:
            result = self.session.get(url=_endpoint, headers=raw_headers)
            return result
        except Exception as e:
            log.error('Exception while making REST call - {}'.format(e))
            return False

    def get_licences_all(self):
        """
        Get a full licence count
        :return:
        """
        raw_headers = {"Authorization": "Bearer " + self.auth['access_token'], "Content-type": "application/json"}
        _endpoint = config["apiurl"] + "/subscribedSkus"

        try:
            result = self.session.get(url=_endpoint, headers=raw_headers)
            return result.json()
        except Exception as e:
            log.error('Exception while making REST call - {}'.format(e))
            return False

    def lic_mon(self, threshold=5):
        """
        Monitor and report licence thresholds
        :param threshold:
        :return:
        """
        _lics = self.get_licences_o365e5()
        if not _lics:
            liclog.error('Failed to get licence data')
            return
        lics = _lics.json()
        free_lics = int(lics['prepaidUnits']['enabled']) - int(lics['consumedUnits'])
        if (free_lics) < threshold:
            liclog.error("O365 remaining licence count is {}. "
                         "Failed free licence threshold of {}.".format(free_lics, threshold))
        else:
            liclog.info("O365 remaining licence count is {}. Licence status OK".format(free_lics))
