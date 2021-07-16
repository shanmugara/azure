import msal
import requests
import json
import os
import sys
import urllib3
import platform
import base64
import re

from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from az.helpers import my_logger
from az.helpers.config import config, app_secret, cert_key_path, cert_path
from az.helpers import powershell

if platform.system().lower() == 'windows':
    LOG_DIR = os.path.join('c:\\', 'logs', 'azgraph')
else:
    LOG_DIR = os.path.join(os.environ['VIRTUAL_ENV'], 'logs', 'azgraph')

log = my_logger.My_logger(logdir=LOG_DIR, logfile='azuread')
liclog = my_logger.My_logger(logdir=LOG_DIR, logfile='licence')
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class AzureAd(object):
    class DupObj(object):
        def __init__(self, name):
            self.name = name

        def __repr__(self):
            return self.name

        def __str__(self):
            return self.name

    def __init__(self, proxy=config["proxy"]):
        # Initialize authentication and get token

        client_id = config["client_id"]
        client_secret = config["client_secret"]
        scope = config["scope"]
        authority = config["authority"]

        if config["cert_auth"]:
            client_credentials = self.get_cert_creds()
        else:
            username = config["username"]
            pwd = base64.b64decode(config['password'].decode("utf-8")).decode()
            client_credentials = client_secret

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self.session = requests.Session()
        if proxy is not None:
            self.session.proxies = proxy
        retries = Retry(total=5, backoff_factor=1, status_forcelist=[502, 503, 504])
        self.session.mount("http://", HTTPAdapter(max_retries=retries))
        self.session.mount("https://", HTTPAdapter(max_retries=retries))

        self.app = msal.ClientApplication(
            client_id,
            authority=authority,
            client_credential=client_credentials,
            proxies=config['proxy']
        )

        self.auth = None
        # Firstly, check the cache to see if this end user has signed in before
        accounts = self.app.get_accounts(username=username)
        if accounts:
            log.info("Account(s) exists in cache, probably with token too. Let's try.")
            self.auth = self.app.acquire_token_silent(scope, account=accounts[0])

        if not self.auth:
            log.info("No suitable token exists in cache. Let's get a new one from AAD.")
            # See this page for constraints of Username Password Flow.
            # https://github.com/AzureAD/microsoft-authentication-library-for-python/wiki/Username-Password-Authentication

            self.auth = self.app.acquire_token_by_username_password(username, pwd, scopes=scope)

        if "access_token" in self.auth:
            # Test Calling graph using the access token
            _endpoint = config["apiurl"] + "/users"
            graph_data = self.session.get(  # Use token to call downstream service
                _endpoint,
                headers={'Authorization': 'Bearer ' + self.auth['access_token']}, ).json()
            # print("Graph API call self.auth: %s" % json.dumps(graph_data, indent=2))
        else:
            log.error(self.auth.get("error"))
            log.error(self.auth.get("error_description"))
            log.error(self.auth.get("correlation_id"))  # You may need this when reporting a bug
            if 65001 in self.auth.get("error_codes", []):  # Not mean to be coded programatically, but...
                # AAD requires user consent for U/P flow
                log.error("Visit this to consent:", self.app.get_authorization_request_url(config["scope"]))

    def get_cert_creds(self):
        """
        Get cert creds dict
        :return:
        """
        if all([os.path.isfile(cert_path), os.path.isfile(cert_key_path)]):
            with open(cert_path) as f:
                cert_file = f.read()
            with open(cert_key_path) as f:
                key_file = f.read()

                # Create an X509 object and calculate the thumbprint
                cert_obj = load_pem_x509_certificate(data=bytes(cert_file, 'UTF-8'), backend=default_backend())
                thumbprint = (cert_obj.fingerprint(hashes.SHA1()).hex())

                client_credential = {
                    "private_key": key_file,
                    "thumbprint": thumbprint,
                    "public_certificate": cert_file
                }

                return client_credential

        else:
            log.error('Missing cert/cert_key files')
            return False

    def get_aad_user(self, displayname=None, loginid=None, onprem=False):
        """
        Search for a user by displayname. This is a wildcard search.
        :param displayname: display name
        :param loginid: samaccountname
        :param onprem: get only on prem synced accounts
        :return:
        """

        raw_headers = {"Authorization": "Bearer " + self.auth['access_token'], "ConsistencyLevel": "eventual"}

        if displayname:
            query_str = "?$filter=displayName eq '{}'".format(displayname)
        elif loginid:
            query_str = "?$filter=startswith(userPrincipalname, '{}@')".format(loginid)
        else:
            filter = "?$select=onPremisesSyncEnabled,id,userPrincipalName,businessPhones,displayName,givenName," \
                     "jobTitle,mail,mobilePhone,officeLocation,surname"
            query_str = filter
        page = True
        allusers_full = []
        _endpoint = config["apiurl"] + "/users" + query_str

        while page:
            result = self.session.get(_endpoint, headers=raw_headers)
            users_dict = result.json()
            users_list = users_dict['value']
            allusers_full.extend(users_list)
            if '@odata.nextLink' in users_dict.keys():
                _endpoint = users_dict['@odata.nextLink']
            else:
                page = False

        allusers = []

        if onprem:
            for u in allusers_full:
                if u['onPremisesSyncEnabled'] == True:
                    allusers.append(u)
        else:
            allusers = allusers_full

        return allusers

    def get_ext_attr(self, displayname):
        user = self.get_aad_user(displayname=displayname)
        oid = user['value'][0]['id']
        print(oid)
        query_str = "/{}?$select=extm7dsnjo8_adatumext".format(oid)

        raw_headers = {"Authorization": "Bearer " + self.auth['access_token']}
        _endpoint = config["apiurl"] + "/users" + query_str
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
        _endpoint = config["apiurl"] + "/users" + query_str

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
        _endpoint = config["apiurl"] + "/users/{}/extensions".format(oid)
        result = self.session.post(url=_endpoint, data=data_json, headers=raw_headers)

        return result

    def get_aad_group(self, groupname=None):
        """
        Get an AAD group properties
        :param groupname:
        :return:
        """
        raw_headers = {"Authorization": "Bearer " + self.auth['access_token'],
                       "ConsistencyLevel": "eventual"}

        if groupname:
            query_str = "?$filter=displayName eq '{}'".format(groupname)
        else:
            query_str = ''

        _endpoint = config["apiurl"] + "/groups" + query_str

        try:
            result = self.session.get(_endpoint,
                                      headers=raw_headers)
            return result.json()
        except Exception as e:
            log.error('Exception while getting group from AAD - {}'.format(e))
            return None

    def make_aad_grp_id_map(self):
        """
        create a dict with id:group
        :return:
        """
        self.all_aad_grp_ids = {}
        _groups = self.get_aad_group()
        for g in _groups['value']:
            self.all_aad_grp_ids[g['id']] = g['displayName']

    def get_aad_members(self, groupname):
        """
        Get members of an AAD groups
        :param groupname:
        :return:
        """
        raw_headers = {"Authorization": "Bearer " + self.auth['access_token']}

        group_obj = self.get_aad_group(groupname=groupname)
        if group_obj:
            gid = group_obj['value'][0]['id']
            query_str = "/groups/{}/members".format(gid)
            _endpoint = config['apiurl'] + query_str

            try:
                result = self.session.get(_endpoint, headers=raw_headers)
                ret_dict = result.json()
                ret_dict['group_id'] = gid
                ret_dict['group_name'] = groupname
                return ret_dict
            except Exception as e:
                log.error('Error while getting group members for "{}" - {}'.format(group_obj, e))
        else:
            log.error('Did not get a group object for "{}"'.format(groupname))

    def aad_user_upn_map(self, onprem=True):
        """
        Create a dict with user upn without @xxx.xxx.xxx and id
        :return:
        """
        all_aad_users = self.get_aad_user(onprem=onprem)
        self.upn_id_map = {}

        if all_aad_users:
            for u in all_aad_users:
                upn_short = u['userPrincipalName'].split('@')[0].lower()
                self.upn_id_map[upn_short] = u['id']
        else:
            log.error('Failed to get users list from AAD')
            return False

    def sync_group(self, adgroup, clgroup):
        """
        Get group members from AD synced group and add to cloud group, and remove members not in ad group.
        ad group is retrieved from on-prem ad. required quest powershell module for ad.
        :param adgroup: on prem ad group name
        :param clgroup: azure ad cloud group name
        :return:
        """
        log.info('Start syncing AD group "{}" to cloud group "{}"'.format(adgroup, clgroup))
        if not hasattr(self, 'all_aad_grp_ids'):
            self.make_aad_grp_id_map()

        if not hasattr(self, 'upn_id_map'):
            self.aad_user_upn_map(onprem=True)

        adgroup_members = powershell.get_adgroupmember(groupname=adgroup)

        self.cldgroup_members_full = self.get_aad_members(groupname=clgroup)

        if len(self.cldgroup_members_full['value']) == 0:
            is_cldgroup_null = True
        else:
            is_cldgroup_null = False

        # cldgroup_ids = []
        cldgroup_members = []

        if not is_cldgroup_null:
            for user in self.cldgroup_members_full['value']:
                cld_upn_short = user['userPrincipalName'].split('@')[0].lower()
                # cldgroup_ids.append(user['id'])
                cldgroup_members.append(cld_upn_short.lower())

        mem_not_in_cld = set(adgroup_members) - set(cldgroup_members)
        mem_not_in_ad = set(cldgroup_members) - set(adgroup_members)

        log.info('Members list to be removed from cloud group "{}" - {}'.format(clgroup, list(mem_not_in_ad)))
        log.info('Members list to be added to cloud group "{}" - {}'.format(clgroup, list(mem_not_in_cld)))

        # add missing members to cld group
        if mem_not_in_cld:
            log.info('Adding new users {} to cloud group "{}"'.format(list(mem_not_in_cld), clgroup))

            mem_to_add_to_cld = []

            for u in list(mem_not_in_cld):
                try:
                    mem_to_add_to_cld.append(self.upn_id_map[u])
                except KeyError:
                    log.error(
                        'adsynced user id: {} was not found azure ad. '
                        'User will not be added to group: {}'.format(u, clgroup))

            if mem_to_add_to_cld:
                result = self.add_members_blk(uidlist=mem_to_add_to_cld, gid=self.cldgroup_members_full['group_id'])
                log.info('Status code: {}'.format(result.status_code))
        else:
            log.info('No new users to be added to group "{}"'.format(clgroup))

        if mem_not_in_ad:
            log.info('Deleting users {} from cloud group "{}"'.format(list(mem_not_in_ad), clgroup))
            for s_upn in list(mem_not_in_ad):
                log.info('Deleting {}'.format(s_upn))

                try:
                    result = self.remove_member(userid=self.upn_id_map[s_upn],
                                                gid=self.cldgroup_members_full['group_id'])
                    log.info('Status code: {}'.format(result.status_code))
                except KeyError:
                    log.error('Unable to find adsynced user {} in azure ad'.format(s_upn))
                except Exception as e:
                    log.error('Exception was thrown while removing id: {} from group: {}'.format(s_upn, clgroup))

        else:
            log.info('No users need to be removed from cloud group "{}"'.format(clgroup))

    def add_member(self, userid, gid):
        """
        Add a single user to a group
        :param userid:
        :param gid:
        :return:
        """
        raw_headers = {"Authorization": "Bearer " + self.auth['access_token'], "Content-type": "application/json",
                       "Content-length": "30"}
        query_str = '/groups/{}/members/$ref'.format(gid)
        _endpoint = config['apiurl'] + query_str

        data_dict = {
            '@odata.id': config['apiurl'] + '/directoryObjects/{}'.format(userid)
        }
        data_json = json.dumps(data_dict)
        try:
            result = self.session.post(url=_endpoint, data=data_json, headers=raw_headers)
            return result

        except Exception as e:
            log.error('Exception {} while adding users to group "{}"'.format(e, gid))
            return False

    def add_members_blk(self, uidlist, gid):
        """
        Add multiple users to a group
        :param uidlist:
        :param gid:
        :return:
        """
        raw_headers = {"Authorization": "Bearer " + self.auth['access_token'], "Content-type": "application/json"}
        _endpoint = config['apiurl'] + '/groups/{}'.format(gid)

        data_dict = {"members@odata.bind": []}
        for uid in uidlist:
            try:
                if isinstance(self.all_aad_grp_ids, dict):
                    grp = self.all_aad_grp_ids[gid]
                else:
                    grp = gid

                log.info('ADD: group:{} uid:{} displayName:{}'.format(grp, uid, self.adgroups_dict[uid]))
            except:
                pass
            uid_url = 'https://graph.microsoft.com/v1.0/users/{}'.format(uid)
            data_dict["members@odata.bind"].append(uid_url)

        data_json = json.dumps(data_dict)

        try:
            result = self.session.patch(url=_endpoint, data=data_json, headers=raw_headers)
            return result

        except Exception as e:
            log.error('Exception while adding users to group "{}"'.format(gid))
            return False

    def remove_member(self, userid, gid):
        """
        Remove a user from group
        :param userid:
        :param gid:
        :return:
        """
        raw_headers = {"Authorization": "Bearer " + self.auth['access_token'], "Content-type": "application/json"}
        _endpoint = config['apiurl'] + '/groups/{}/members/{}/$ref'.format(gid, userid)

        try:
            grp = self.all_aad_grp_ids[gid]
        except:
            grp = gid

        try:
            log.info('REMOVE: group:{} uid:{} displayName:{}'.format(grp, userid, self.cldgroups_dict[userid]))
        except:
            pass

        try:
            result = self.session.delete(url=_endpoint, headers=raw_headers)
            # log.info(result.status_code)
            return result
        except Exception as e:
            log.error('Exception while deleteing user {} from group {}'.format(userid, gid))
            return False

    def get_open_extensions(self, oid):
        """
        Get open extensions from user
        :param oid:
        :return:
        """
        raw_headers = {"Authorization": "Bearer " + self.auth['access_token'], "Content-type": "application/json"}
        _endpoint = config["apiurl"] + "/users/{}/extensions".format(oid)

        try:
            result = self.session.get(url=_endpoint, headers=raw_headers)
            return result.json()

        except Exception as e:
            log.error('Exception while making REST call - {}'.format(e))
            return False

    def get_licences_all(self, guid=None):
        """
        Get a full licence count
        :return:
        """
        raw_headers = {"Authorization": "Bearer " + self.auth['access_token'], "Content-type": "application/json"}
        _endpoint = config["apiurl"] + "/subscribedSkus"
        if guid:
            _endpoint += '/{}'.format(guid)

        try:
            result = self.session.get(url=_endpoint, headers=raw_headers)
            return result.json()
        except Exception as e:
            log.error('Exception while making REST call - {}'.format(e))
            return False

    def licence_map(self):
        """
        Create a licence refernce map with string:guid
        :return:
        """
        lics = self.get_licences_all()
        self.lic_map = {}
        for l in lics['value']:
            self.lic_map[l['skuPartNumber'].lower()] = l['id']

    def lic_mon(self, skuname, threshold=5):
        """
        Monitor and report licence thresholds
        :param threshold:
        :return:
        """
        if not hasattr(self, 'lic_map'):
            self.licence_map()
        if skuname.lower() in self.lic_map.keys():
            lics = self.get_licences_all(guid=self.lic_map[skuname.lower()])
        else:
            log.error('Invalid SKU name, or SKU {} doesnt exist in organization'.format(skuname.upper()))
            return False

        if not lics:
            liclog.error('Failed to get licence data')
            return

        free_lics = int(lics['prepaidUnits']['enabled']) - int(lics['consumedUnits'])
        if (free_lics) < threshold:
            liclog.error("{} remaining licence count is {}. "
                         "Failed free licence threshold of {}.".format(skuname.upper(), free_lics, threshold))
        else:
            liclog.info("{} remaining licence count is {}. Licence status OK".format(skuname.upper(), free_lics))

    def get_user_license(self, uid):
        """
        Get license details for teh given user
        :param uid:
        :return:
        """

        raw_headers = {"Authorization": "Bearer " + self.auth['access_token'], "Content-type": "application/json"}
        _endpoint = config["apiurl"] + "/users/{}/licenseDetails".format(uid)

        try:
            result = self.session.get(url=_endpoint, headers=raw_headers)
            return result.json()
        except Exception as e:
            log.error('Exception while making REST call - {}'.format(e))
            return False

    def report_license_activation(self):
        """
        Generate Activation report dict
        :return:
        """
        raw_headers = {"Authorization": "Bearer " + self.auth['access_token'], "Content-type": "application/json"}
        _endpoint = config["apiurl"] + "/reports/getOffice365ActivationsUserDetail"

        try:
            result = self.session.get(url=_endpoint, headers=raw_headers)
            raw_l = result.text.splitlines()
            raw_l.pop(0)
            raw_dict = {}
            re_pat = re.compile('".+"')
            for i in raw_l:
                print(i)
                if re.search(re_pat, i):
                    line = re.sub(re_pat, '', i)
                    date, upn, disp, p_type, last_act, win, mac, win10m, ios, android, shared = i.split(',')
                    disp = re.search(re_pat, i).group()
                else:
                    date, upn, disp, p_type, last_act, win, mac, win10m, ios, android, shared = i.split(',')

                u_o = self.DupObj(upn)
                raw_dict[u_o] = {}
                raw_dict[u_o]['display_name'] = disp
                raw_dict[u_o]['product_type'] = p_type
                raw_dict[u_o]['last_activated'] = last_act
                raw_dict[u_o]['windows'] = win
                raw_dict[u_o]['macos'] = mac
                raw_dict[u_o]['win10mobile'] = win10m
                raw_dict[u_o]['ios'] = ios
                raw_dict[u_o]['android'] = android
                raw_dict[u_o]['sharedcomp'] = shared

            return raw_dict, result
        except Exception as e:
            log.error('Exception while making REST call - {}'.format(e))
            return False
