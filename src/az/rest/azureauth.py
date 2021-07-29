import msal
import requests
import json
import os
import sys
import urllib3
import platform
import base64
import re
import functools
import timeit
from datetime import datetime

from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from az.helpers import my_logger
from az.helpers.config import config, cert, user
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

    class Timer(object):
        """
        Generic timer
        :return: wrapped func
        """

        @staticmethod
        def add_timer(func):
            functools.wraps(func)

            def timed_func(*args, **kwargs):  # Inner func return func
                start_time = timeit.default_timer()
                func_results = func(*args, **kwargs)
                end_time = timeit.default_timer()
                elapsed_time = end_time - start_time
                log.info(
                    "Function {} - Elapsed time: {}".format(
                        func.__name__, round(elapsed_time, 3)
                    )
                )
                return func_results

            return timed_func

    def __init__(self, proxy=config["proxy"], cert_auth=config["cert_auth"]):
        # Initialize authentication and get token
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self.session = requests.Session()

        if proxy is not None:
            self.session.proxies = proxy

        retries = Retry(total=5, backoff_factor=1, status_forcelist=[502, 503, 504])
        self.session.mount("http://", HTTPAdapter(max_retries=retries))
        self.session.mount("https://", HTTPAdapter(max_retries=retries))

        self.cert_auth = cert_auth

        if self.cert_auth:
            self.client_credentials = self.get_cert_creds()
            self.init_app_confidential()
        else:
            self.client_credentials = user["client_secret"]
            self.init_app()

        self.init_token()

    def init_app(self):
        """
        Init msal auth
        :return:
        """
        self.app = msal.ClientApplication(
            config["client_id"],
            authority=config["authority"],
            client_credential=self.client_credentials,
            proxies=config['proxy']
        )

    def init_app_confidential(self):
        """
        Init msal confidential auth
        :return:
        """
        self.app = msal.ConfidentialClientApplication(
            client_id=config["client_id"],
            authority=config["authority"],
            client_credential=self.client_credentials,
            proxies=config['proxy']
        )

    def init_token(self):
        """
        Get an auth token
        :return:
        """
        self.auth = None
        # Firstly, check the cache to see if this end user has signed in before
        if self.cert_auth:
            log.info('Obtaining new auth token by certificate and key pair')
            self.auth = self.app.acquire_token_for_client(scopes=cert['scope'])
        else:
            accounts = self.app.get_accounts(username=user["username"])
            if accounts:
                log.info("Account(s) exists in cache, probably with token too. Let's try.")
                self.auth = self.app.acquire_token_silent(config["scope"], account=accounts[0])

            if not self.auth:
                log.info("Obtaining new auth token by username and password.")
                # See this page for constraints of Username Password Flow.
                # https://github.com/AzureAD/microsoft-authentication-library-for-python/wiki/Username-Password-Authentication
                pwd = base64.b64decode(user['password'].decode("utf-8")).decode()
                self.auth = self.app.acquire_token_by_username_password(user["username"], pwd, scopes=user["scope"])

        if "access_token" in self.auth:
            log.info('Successfully obtained auth token.')

        else:
            log.error(self.auth.get("error"))
            log.error(self.auth.get("error_description"))
            log.error(self.auth.get("correlation_id"))
            if 65001 in self.auth.get("error_codes", []):
                # AAD requires user consent for U/P flow
                log.error("Visit this to consent:{}".format('...'))

    def get_cert_creds(self):
        """
        Get cert creds dict
        :return:
        """
        if all([os.path.isfile(cert['cert_path']), os.path.isfile(cert['cert_key_path'])]):
            with open(cert['cert_path']) as f:
                cert_file = f.read()
            with open(cert['cert_key_path']) as f:
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
            log.error('Missing cert/cert_key files. Unable to generate cert creds..')
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
            filter = "?$top=900&$select=onPremisesSyncEnabled,id,userPrincipalName,businessPhones,displayName,givenName," \
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
            return False

    @Timer.add_timer
    def make_aad_grp_id_map(self):
        """
        create a dict with id:group
        :return:
        """
        self.all_aad_grp_ids = {}
        _groups = self.get_aad_group()
        for g in _groups['value']:
            self.all_aad_grp_ids[g['id']] = g['displayName']

    @Timer.add_timer
    def get_aad_members(self, groupname):
        """
        Get members of an AAD groups
        :param groupname:
        :return:
        """
        raw_headers = {"Authorization": "Bearer " + self.auth['access_token']}

        group_obj = self.get_aad_group(groupname=groupname)
        if all([group_obj, group_obj['value']]):
            gid = group_obj['value'][0]['id']
            query_str = "/groups/{}/members".format(gid)
            _endpoint = config['apiurl'] + query_str
            page = True
            ret_dict = {}
            ret_dict['group_id'] = gid
            ret_dict['group_name'] = groupname
            ret_dict['value'] = []

            while page:
                try:
                    result = self.session.get(_endpoint, headers=raw_headers)
                    ret_dict['value'].extend(result.json()['value'])
                    if '@odata.nextLink' in result.json().keys():
                        _endpoint = result.json()['@odata.nextLink']
                    else:
                        page = False

                except Exception as e:
                    log.error('Error while getting group members for "{}" - {}'.format(group_obj, e))
                    page = False

            return ret_dict

        else:
            log.error('Did not get a Azure AD group object for "{}"'.format(groupname))
            return False

    @Timer.add_timer
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

    def sync_group_json(self, filename):
        """
        Use a json file as input for calling sync_group. file format is adgroup:cldgroup
        sample input json file format"
        --start--
        {
            "myadgroup1": "mycloudgroup1",
            "myadgroup2": "mycloudgroup2"
        }
        --end--
        :param filename:
        :return:
        """
        if os.path.isfile(filename):
            try:
                with open(filename) as f:
                    log.info('loading file {}'.format(filename))
                    syn_group_dict = json.load(f)
                    log.info('processing groups from sync file..')
                    for g in syn_group_dict:
                        self.sync_group(adgroup=g, clgroup=syn_group_dict[g], test=False)
                    log.info('finished processing sync file..')

            except Exception as e:
                log.error('Exception while loading file. Exception: {}'.format(e))

        else:
            log.error('Invalid file path.. "{}"'.format(filename))

    @Timer.add_timer
    def sync_group(self, adgroup, clgroup, test=False):
        """
        Get group members from on-prem AD group and add to a AAD cloud group, and remove members not in on-prem AD group
        from cloud group. AD group is retrieved from on-prem ad. requires quest powershell module for ad. On-prem AD group
        does not need to be synced to azure ad using AAD sync.
        :param adgroup: on prem ad group name
        :param clgroup: azure ad cloud group name
        :param test: test mode with no writes (bool)
        :return:
        """

        log.info('Start syncing AD group "{}" to cloud group "{}"'.format(adgroup, clgroup))
        if not hasattr(self, 'all_aad_grp_ids'):
            self.make_aad_grp_id_map()

        if not hasattr(self, 'upn_id_map'):
            self.aad_user_upn_map(onprem=True)

        adgroup_members = powershell.get_adgroupmember(groupname=adgroup)
        if adgroup_members == False:
            log.error('Unable to get on-prem AD group members for "{}". Check group name. Exiting.'.format(adgroup))
            return False

        self.cldgroup_members_full = self.get_aad_members(groupname=clgroup)

        if self.cldgroup_members_full == False:
            log.error('Unable to get Azure AD goup "{}". Check group name. Exiting.'.format(clgroup))
            return False

        if len(self.cldgroup_members_full['value']) == 0:
            is_cldgroup_null = True
        else:
            is_cldgroup_null = False

        cldgroup_members = []

        if not is_cldgroup_null:
            for user in self.cldgroup_members_full['value']:
                cld_upn_short = user['userPrincipalName'].split('@')[0].lower()
                cldgroup_members.append(cld_upn_short.lower())

        mem_not_in_cld = set(adgroup_members) - set(cldgroup_members)
        mem_not_in_ad = set(cldgroup_members) - set(adgroup_members)

        log.info('Members list to be added to cloud group "{}" - {}'.format(clgroup, list(mem_not_in_cld)))

        # add missing members to cld group
        if mem_not_in_cld:
            mem_to_add_to_cld = []
            not_in_aad = []

            for u in list(mem_not_in_cld):
                try:
                    mem_to_add_to_cld.append(self.upn_id_map[u])
                except KeyError:
                    not_in_aad.append(u)
            if not_in_aad:
                log.error(
                    'on-prem AD users {} not found in Azure AD. This may be a transient AAD Sync delay.'
                    'These users will not be added to group "{}" in this cycle.'.format(not_in_aad, clgroup))

            if mem_to_add_to_cld:
                log.info(
                    'Adding new members {} to cloud group "{}"'.format(
                        list(set(mem_not_in_cld) - set(list(not_in_aad))),
                        clgroup))
                result = self.add_members_blk(uidlist=mem_to_add_to_cld, gid=self.cldgroup_members_full['group_id'],
                                              test=test)
                if result:
                    log.info('Bulk add result code: OK')
                else:
                    log.error('Bulk add result code: FAILED')
        else:
            log.info('No new members to be added to group "{}"'.format(clgroup))

        log.info('Members list to be removed from cloud group "{}" - {}'.format(clgroup, list(mem_not_in_ad)))
        if mem_not_in_ad:
            log.info('Deleting members {} from cloud group "{}"'.format(list(mem_not_in_ad), clgroup))
            for s_upn in list(mem_not_in_ad):
                log.info('Deleting "{}" from group "{}"'.format(s_upn, clgroup))

                try:
                    result = self.remove_member(userid=self.upn_id_map[s_upn],
                                                gid=self.cldgroup_members_full['group_id'], test=test)
                    if test:
                        log.info('Test mode...')
                        continue

                    log.info('Status code: {}'.format(result.status_code))

                except KeyError:
                    log.error('Unable to find adsynced user {} in azure ad'.format(s_upn))
                except Exception as e:
                    log.error(
                        'Exception "{}" was thrown while removing id: {} from group: {}'.format(e, s_upn, clgroup))

        else:
            log.info('No members need to be removed from cloud group "{}"'.format(clgroup))

    def add_member(self, userid, gid):
        """
        Add a single user to a group
        :param userid: azure ad user guid
        :param gid: azure ad group guid
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

    @Timer.add_timer
    def add_members_blk(self, uidlist, gid, test):
        """
        Add multiple users to a group. If max number of user is larger than 20, use subsets
        :param uidlist:
        :param gid:
        :return:
        """

        ret_result = True
        if len(uidlist) > 20:
            log.info("Total number of users {} is greater than 20. We'll add in sets of 20".format(len(uidlist)))
            while len(uidlist) > 0:
                count = 20 if len(uidlist) > 20 else len(uidlist)
                uidsubset = [uidlist.pop(0) for n in range(count)]

                log.info('Adding user set {} to group'.format(uidsubset))
                result = self.add_mem_blk_sub(uidlist=uidsubset, gid=gid, test=test)

                if test:
                    log.info('Test mode...')
                    continue

                log.info('Status code:{}'.format(result.status_code))
                if result == False: return False
                if all([ret_result == True, result.status_code != int(204)]):
                    ret_result = False
        else:
            result = self.add_mem_blk_sub(uidlist=uidlist, gid=gid, test=test)
            if test:
                log.info('Test mode...')
                return ret_result

            log.info('Status code:{}'.format(result.status_code))
            if result == False: return False

            if result.status_code != int(204):
                log.error('Status code:{}'.format(result.status_code))
                ret_result = False

        return ret_result

    def add_mem_blk_sub(self, uidlist, gid, test):
        """
        A sub func to add bulk users to a group. This is to handle max 20 member limit in graph api call.
        :param uidlist:
        :return:
        """
        raw_headers = {"Authorization": "Bearer " + self.auth['access_token'], "Content-type": "application/json"}
        _endpoint = config['apiurl'] + '/groups/{}'.format(gid)

        data_dict = {"members@odata.bind": []}

        for uid in uidlist:
            try:
                uid_url = 'https://graph.microsoft.com/v1.0/users/{}'.format(uid)
                data_dict["members@odata.bind"].append(uid_url)
            except Exception as e:
                log.error('Exception {} in add_members_blk'.format(e))

        data_json = json.dumps(data_dict)

        if not test:
            try:
                result = self.session.patch(url=_endpoint, data=data_json, headers=raw_headers)
                return result

            except Exception as e:
                log.error('Exception while adding users to group "{}"'.format(gid))
                return False
        else:
            log.info('Running in test mode, no writes performed.')
            return None

    @Timer.add_timer
    def remove_member(self, userid, gid, test):
        """
        Remove a user from group
        :param userid: azure ad user object id
        :param gid: azure ad group object id
        :return:
        """
        raw_headers = {"Authorization": "Bearer " + self.auth['access_token'], "Content-type": "application/json"}
        _endpoint = config['apiurl'] + '/groups/{}/members/{}/$ref'.format(gid, userid)

        if not test:
            try:
                result = self.session.delete(url=_endpoint, headers=raw_headers)
                return result
            except Exception as e:
                log.error('Exception while deleteing user {} from group {}'.format(userid, gid))
                return False
        else:
            log.info('Running in test mode, no writes performed')
            return None

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

    def lic_mon(self, skuname, percentage=25, threshold=5):
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

        if lics == False:
            liclog.error('Failed to get licence data')
            return

        free_lics = int(lics['prepaidUnits']['enabled']) - int(lics['consumedUnits'])
        used_percentage = (int(lics['consumedUnits']) / int(lics['prepaidUnits']['enabled'])) * 100
        free_percentage = round(100 - used_percentage)

        if threshold:
            if (free_lics) < threshold:
                liclog.error("{} Total: {} remaining licence count is {}."
                             "Failed free licence threshold of {}.".format(skuname.upper(),
                                                                           int(lics['prepaidUnits']['enabled']),
                                                                           free_lics,
                                                                           threshold))
            else:
                liclog.info(
                    "{} Total: {}. Remaining licence count is {}. Licence status OK".format(skuname.upper(), int(
                        lics['prepaidUnits']['enabled']), free_lics))
        if percentage:
            if (free_percentage) < int(percentage):
                liclog.error("{} Total: {}. Free percentage is {}%"
                             " Failed free licence threshold of {}%.".format(skuname.upper(),
                                                                             int(lics['prepaidUnits']['enabled']),
                                                                             free_percentage, percentage))
            else:
                liclog.info(
                    "{} Total: {}. Free percentage {}%. Licence status OK".format(skuname.upper(),
                                                                                  int(lics['prepaidUnits']['enabled']),
                                                                                  free_percentage))

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

    def report_license_activation(self, outdir):
        """
        Generate Activation report dict
        outpath: p = "\\\\corp.bloomberg.com\\ny-dfs\\Ops\\InfoSys\\Systems Engineering\\Dropboxes\\O365Activations"
        :return:
        """
        raw_headers = {"Authorization": "Bearer " + self.auth['access_token'], "Content-type": "application/json"}
        _endpoint = config["apiurl"] + "/reports/getOffice365ActivationsUserDetail"

        try:
            result = self.session.get(url=_endpoint, headers=raw_headers)
            log.info('Response reason:{} code:{}'.format(result.reason, result.status_code))
            raw_l = result.text.splitlines()
            raw_l.pop(0)
            raw_dict = {}
            re_pat = re.compile('".+"')

            for i in raw_l:
                if re.search(re_pat, i):
                    line = re.sub(re_pat, '', i)
                    date, upn, disp, p_type, last_act, win, mac, win10m, ios, android, shared = line.split(',')
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

            # write csv file
            file_out_lines = []
            header = 'Date,User Principal Name,Display Name,Product Type,Last Activated Date,Windows,Mac,' \
                     'Windows 10 Mobile,iOS,Android,Activated On Shared Computer'
            file_out_lines.append('{}\n'.format(header))

            for l in raw_l:
                file_out_lines.append('{}\n'.format(l))

            epoch_now = str(int((datetime.now()).timestamp()))
            fname_csv = 'licact_report_{}.csv'.format(epoch_now)
            # fname_json = 'licact_report_{}.json'.format(epoch_now)

            if os.path.isdir(outdir):
                outfile_csv = os.path.join(outdir, fname_csv)
                with open(outfile_csv, 'w') as f:
                    f.writelines(file_out_lines)
            else:
                log.error('Destination path "{}" doesnt exist or unreachable'.format(outdir))

                # outfile_json = os.path.join(outdir, fname_json)
                # with open(outfile_json, 'w') as j:
                #     json.dump(raw_dict, j)
            return raw_dict

        except Exception as e:
            log.error('Exception while making REST call - {}'.format(e))
            return False