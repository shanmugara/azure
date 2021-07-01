import msal
from config import config
import logging
import requests
import json

logging.basicConfig(level=logging.INFO)
class AzureAd(object):

    def __init__(self):

        self.app = msal.ClientApplication(
            config["client_id_lic"],
            authority=config["authority"],
            client_credential=config.get("client_secret_lic")
        )

        self.auth = None
        # Firstly, check the cache to see if this end user has signed in before
        accounts = self.app.get_accounts(username=config["username"])
        if accounts:
            logging.info("Account(s) exists in cache, probably with token too. Let's try.")
            self.auth = self.app.acquire_token_silent(config["scope"], account=accounts[0])

        if not self.auth:
            logging.info("No suitable token exists in cache. Let's get a new one from AAD.")
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
            print(self.auth.get("error"))
            print(self.auth.get("error_description"))
            print(self.auth.get("correlation_id"))  # You may need this when reporting a bug
            if 65001 in self.auth.get("error_codes", []):  # Not mean to be coded programatically, but...
                # AAD requires user consent for U/P flow
                print("Visit this to consent:", self.app.get_authorization_request_url(config["scope"]))

    def search_user(self, displayname):

        raw_headers = {"Authorization": "Bearer " + self.auth['access_token'],
                       "ConsistencyLevel": "eventual"}

        query_str = '?$search="displayName:{}"'.format(displayname)
        _endpoint = config["endpoint"] + query_str
        print(_endpoint)
        result = requests.get(_endpoint,
                              headers=raw_headers)
        return result.json()

    def get_ext_attr(self, displayname):
        user = self.search_user(displayname=displayname)
        oid = user['value'][0]['id']
        print(oid)
        query_str = "/{}?$select=extm7dsnjo8_adatumext".format(oid)

        raw_headers = {"Authorization": "Bearer " + self.auth['access_token']}
        _endpoint = config["endpoint"] + query_str
        print(_endpoint)
        result = requests.get(_endpoint,
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
        print(_endpoint)

        result = requests.patch(url=_endpoint, data=data_json, headers=raw_headers)

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
        result = requests.post(url=_endpoint, data=data_json, headers=raw_headers)

        return result

    def get_open_extensions(self, oid):
        """
        Get open extensions from user
        :param oid:
        :return:
        """
        raw_headers = {"Authorization": "Bearer " + self.auth['access_token'], "Content-type": "application/json"}
        _endpoint = config["endpoint"] + "/{}/extensions".format(oid)

        result = requests.get(url=_endpoint, headers=raw_headers)

        return result

    def get_licences_o365e5(self):
        """
        Get a full licence count of E5
        :return:
        """
        guid = "009ebdb7-1526-4c4e-bdbb-4d6305d2c24e_c7df2760-2c81-4ef7-b578-5b5392b571df"
        raw_headers = {"Authorization": "Bearer " + self.auth['access_token'], "Content-type": "application/json"}
        _endpoint = config["apiurl"] + "/subscribedSkus/{}".format(guid)

        result = requests.get(url=_endpoint, headers=raw_headers)

        return result

    def get_licences_all(self):
        """
        Get a full licence count
        :return:
        """
        raw_headers = {"Authorization": "Bearer " + self.auth['access_token'], "Content-type": "application/json"}
        _endpoint = config["apiurl"] + "/subscribedSkus"

        result = requests.get(url=_endpoint, headers=raw_headers)

        return result

    def lic_mon(self, threshold=5):
        """
        Monitor and report licence thresholds
        :param threshold:
        :return:
        """

        _lics = self.get_licences_o365e5()
        lics = _lics.json()
        if (int(lics['prepaidUnits']['enabled']) - int(lics['consumedUnits'])) < threshold:
            logging.error("Exceeded licence threshold")
        else:
            logging.info("Licence status OK")


