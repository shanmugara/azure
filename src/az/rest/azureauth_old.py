import time

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
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from az.helpers import my_logger
from az.helpers.config import config, cert, user, tenancy
from az.helpers import powershell
from az.helpers import pki_helper


if platform.system().lower() == 'windows':
    LOG_DIR = os.path.join('c:\\', 'logs', 'azgraph')
else:
    LOG_DIR = os.path.join(os.environ['VIRTUAL_ENV'], 'logs', 'azgraph')

log = my_logger.My_logger(logdir=LOG_DIR, logfile='azuread')
liclog = my_logger.My_logger(logdir=LOG_DIR, logfile='licence')



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

    def __init__(self, proxy=config["proxy"], cert_auth=config["cert_auth"], auto_rotate=False, days=30):
        # Initialize authentication and get token
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self.session = requests.Session()

        if proxy is not None:
            self.session.proxies = proxy

        retries = Retry(total=5, backoff_factor=1, status_forcelist=[502, 503, 504])
        self.session.mount("http://", HTTPAdapter(max_retries=retries))
        self.session.mount("https://", HTTPAdapter(max_retries=retries))

        self.cert_auth = cert_auth
        log.info('Current Azure tenancy: {}'.format(tenancy))

        if self.cert_auth:
            self.client_credentials = self.get_cert_creds()
            self.init_app_confidential()
        else:
            self.client_credentials = user["client_secret"]
            self.init_app()

        self.init_token()

        if auto_rotate:
            log.info('Automated cert rotation is enabled. Checking cert valididty.')
            self.rotate_this_cert(days=days)

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

    # def get_aad_user(self, displayname=None, loginid=None, onprem=False):
    #     """
    #     Search for a user by displayname. This is a wildcard search.
    #     :param displayname: display name
    #     :param loginid: samaccountname
    #     :param onprem: get only on prem synced accounts
    #     :return:
    #     """
    #
    #     raw_headers = {"Authorization": "Bearer " + self.auth['access_token'], "ConsistencyLevel": "eventual"}
    #
    #     if displayname:
    #         query_str = "?$filter=displayName eq '{}'".format(displayname)
    #     elif loginid:
    #         query_str = "?$filter=startswith(userPrincipalname, '{}@')".format(loginid)
    #     else:
    #         filter = "?$top=999&$select=onPremisesSyncEnabled,id,userPrincipalName,businessPhones,displayName,givenName," \
    #                  "jobTitle,mail,mobilePhone,officeLocation,surname"
    #         query_str = filter
    #     page = True
    #     allusers_full = []
    #     _endpoint = config["apiurl"] + "/users" + query_str
    #
    #     while page:
    #         result = self.session.get(_endpoint, headers=raw_headers)
    #         users_dict = result.json()
    #         users_list = users_dict['value']
    #         allusers_full.extend(users_list)
    #         if '@odata.nextLink' in users_dict.keys():
    #             _endpoint = users_dict['@odata.nextLink']
    #         else:
    #             page = False
    #
    #     allusers = []
    #
    #     if onprem:
    #         for u in allusers_full:
    #             if u['onPremisesSyncEnabled'] == True:
    #                 allusers.append(u)
    #     else:
    #         allusers = allusers_full
    #
    #     return allusers
    #
    # def get_ext_attr(self, displayname):
    #     user = self.get_aad_user(displayname=displayname)
    #     oid = user['value'][0]['id']
    #     print(oid)
    #     query_str = "/{}?$select=extm7dsnjo8_adatumext".format(oid)
    #
    #     raw_headers = {"Authorization": "Bearer " + self.auth['access_token']}
    #     _endpoint = config["apiurl"] + "/users" + query_str
    #     result = self.session.get(_endpoint,
    #                               headers=raw_headers)
    #
    #     return result.json()
    #
    # def set_user_attr(self, oid, attrname, attrval):
    #     """
    #     Set standard user attributes
    #     :param oid:
    #     :param attrname:
    #     :param attrval:
    #     :return:
    #     """
    #     raw_headers = {"Authorization": "Bearer " + self.auth['access_token'], "Content-type": "application/json"}
    #
    #     data = {attrname: attrval}
    #     data_json = json.dumps(data)
    #     query_str = "/{}".format(oid)
    #     _endpoint = config["apiurl"] + "/users" + query_str
    #
    #     result = self.session.patch(url=_endpoint, data=data_json, headers=raw_headers)
    #
    #     return result
    #
    # def set_open_extension(self, extensionname, extattrname, extattrval, oid):
    #     """
    #     CReate and open extension for user
    #     :param extensionname: open extension name
    #     :param extattrname: extension attribute name
    #     :param extattrval: extension attribute value
    #     :return:
    #     """
    #     raw_headers = {"Authorization": "Bearer " + self.auth['access_token'], "Content-type": "application/json"}
    #
    #     data = {"@odata.type": "microsoft.graph.openTypeExtension",
    #             "extensionName": extensionname,
    #             extattrname: extattrval
    #             }
    #
    #     data_json = json.dumps(data)
    #     _endpoint = config["apiurl"] + "/users/{}/extensions".format(oid)
    #     result = self.session.post(url=_endpoint, data=data_json, headers=raw_headers)
    #
    #     return result
    #
    # def get_aad_group(self, groupname=None):
    #     """
    #     Get an AAD group properties
    #     :param groupname:
    #     :return:
    #     """
    #     raw_headers = {"Authorization": "Bearer " + self.auth['access_token'],
    #                    "ConsistencyLevel": "eventual"}
    #
    #     if groupname:
    #         query_str = "?$filter=displayName eq '{}'".format(groupname)
    #     else:
    #         query_str = ''
    #
    #     _endpoint = config["apiurl"] + "/groups" + query_str
    #
    #     try:
    #         result = self.session.get(_endpoint,
    #                                   headers=raw_headers)
    #         return result.json()
    #     except Exception as e:
    #         logad.error('Exception while getting group from AAD - {}'.format(e))
    #         return False
    #
    # @Timer.add_timer
    # def make_aad_grp_id_map(self):
    #     """
    #     create a dict with id:group
    #     :return:
    #     """
    #     self.all_aad_grp_ids = {}
    #     _groups = self.get_aad_group()
    #     for g in _groups['value']:
    #         self.all_aad_grp_ids[g['id']] = g['displayName']
    #
    # @Timer.add_timer
    # def get_aad_members(self, groupname):
    #     """
    #     Get members of an AAD groups
    #     :param groupname:
    #     :return:
    #     """
    #     raw_headers = {"Authorization": "Bearer " + self.auth['access_token']}
    #
    #     group_obj = self.get_aad_group(groupname=groupname)
    #     if all([group_obj, group_obj['value']]):
    #         gid = group_obj['value'][0]['id']
    #         query_str = "/groups/{}/members".format(gid)
    #         _endpoint = config['apiurl'] + query_str
    #         page = True
    #         ret_dict = {}
    #         ret_dict['group_id'] = gid
    #         ret_dict['group_name'] = groupname
    #         ret_dict['value'] = []
    #
    #         while page:
    #             try:
    #                 result = self.session.get(_endpoint, headers=raw_headers)
    #                 ret_dict['value'].extend(result.json()['value'])
    #                 if '@odata.nextLink' in result.json().keys():
    #                     _endpoint = result.json()['@odata.nextLink']
    #                 else:
    #                     page = False
    #
    #             except Exception as e:
    #                 logad.error('Error while getting group members for "{}" - {}'.format(group_obj, e))
    #                 page = False
    #
    #         return ret_dict
    #
    #     else:
    #         logad.error('Did not get a Azure AD group object for "{}"'.format(groupname))
    #         return False
    #
    # @Timer.add_timer
    # def aad_user_upn_map(self, onprem=True):
    #     """
    #     Create a dict with user upn without @xxx.xxx.xxx and id
    #     :return:
    #     """
    #     all_aad_users = self.get_aad_user(onprem=onprem)
    #     self.upn_id_map = {}
    #
    #     if all_aad_users:
    #         for u in all_aad_users:
    #             upn_short = u['userPrincipalName'].split('@')[0].lower()
    #             self.upn_id_map[upn_short] = u['id']
    #     else:
    #         logad.error('Failed to get users list from AAD')
    #         return False
    #
    # def get_aad_roles(self):
    #     """
    #     Get all AAD roles
    #     :return:
    #     """
    #     raw_headers = {"Authorization": "Bearer " + self.auth['access_token']}
    #     _endpoint = config["apiurl"] + "/directoryRoleTemplates"
    #
    #     try:
    #         result = self.session.get(url=_endpoint, headers=raw_headers)
    #         if result.status_code == 200:
    #             return result.json()
    #         else:
    #             logad.error('Error while getting roles templates')
    #             logad.error('Status code: {}'.format(result.status_code))
    #             return False
    #
    #
    #     except Exception as e:
    #         logad.error('Exception while making API call - {}'.format(e))
    #
    # def make_aad_roles_map(self):
    #     """
    #     Generate a dict of roles {display name: id}
    #     :return:
    #     """
    #     roles = self.get_aad_roles()
    #     self.aad_roles_map = {}
    #     if roles['value']:
    #         for role in roles['value']:
    #             self.aad_roles_map[role['displayName'].lower()] = role['id']
    #
    #     else:
    #         logad.error('Unable to get roles from aad. Giving up.')
    #         return False
    #
    # def create_aad_group(self, groupname, role_enable=True, gtype=None, assign_role=None):
    #     """
    #     Create an Azure AD group
    #     :param groupname: group name
    #     :param gtype: type of group to create
    #     :return:
    #     """
    #     raw_headers = {"Authorization": "Bearer " + self.auth['access_token'], "Content-type": "application/json"}
    #     _endpoint = config["apiurl"] + "/groups"
    #
    #     if gtype == int(365):
    #         group_type = ['Unified']
    #     else:
    #         group_type = []
    #
    #     data_dict = {
    #         'displayName': groupname,
    #         'description': 'Created by API',
    #         'isAssignableToRole': role_enable,
    #         'mailEnabled': False,
    #         'mailNickname': groupname,
    #         'securityEnabled': True,
    #         'groupTypes': group_type
    #
    #     }
    #
    #     data_json = json.dumps(data_dict)
    #     logad.info('Creating group {}'.format(groupname))
    #     try:
    #         resp = self.session.post(url=_endpoint, headers=raw_headers, data=data_json)
    #
    #         if all([role_enable, assign_role]):
    #             logad.info('Assigning role {} to group {}'.format(assign_role, groupname))
    #             group_oid = None
    #             timeout = False
    #             count = 0
    #             while all([not group_oid, not timeout]):
    #                 try:
    #                     group_obj = self.get_aad_group(groupname=groupname)
    #                     group_oid = group_obj['value'][0]['id']
    #                     resp_add_role = self.add_member_to_role(member_oid=group_oid, role_name=assign_role)
    #                     logad.info('Add group to role response: {}'.format(resp_add_role))
    #                 except Exception as e:
    #                     if count == 5:
    #                         timeout = True
    #                         logad.error('Timeout reached. Unable to get group object. Exiting')
    #                         continue
    #                     logad.info('Waiting 5 seconds before retrying..')
    #                     count += 1
    #                     time.sleep(5)
    #
    #         return resp
    #     except Exception as e:
    #         logad.error('Exception was throws while creating group {}, - {}'.format(groupname, e))
    #
    # def add_member_to_role(self, member_oid, role_name):
    #     """
    #     Add a given object ID to a AAD Role
    #     :param member_oid: object ID of user/group
    #     :param role_name: template name of the role, such as "global readers" etc
    #     :return:
    #     """
    #     if not hasattr(self, 'aad_roles_map'):
    #         self.make_aad_roles_map()
    #
    #     if self.aad_roles_map.get(role_name.lower()):
    #         role_template_id = self.aad_roles_map[role_name.lower()]
    #     else:
    #         logad.error('Unable to find template id for role "{}"'.format(role_name))
    #         return False
    #
    #     raw_headers = {"Authorization": "Bearer " + self.auth['access_token'], "Content-type": "application/json"}
    #     _endpoint = config["apiurl"] + "/directoryRoles/roleTemplateId={}/members/$ref".format(role_template_id)
    #
    #     data_dict = {
    #         "@odata.id": "https://graph.microsoft.com/v1.0/directoryObjects/{}".format(member_oid)
    #     }
    #     data_json = json.dumps(data_dict)
    #
    #     try:
    #         resp = self.session.post(url=_endpoint, headers=raw_headers, data=data_json)
    #         if resp.status_code == int(204):
    #             logad.info('Status code: {}'.format(resp.status_code))
    #             return
    #         else:
    #             logad.error('Status code: {}'.format(resp.status_code))
    #             return resp.json()
    #     except Exception as e:
    #         logad.error(
    #             'Exception was thrown while assigning role "{}" to object "{}" - {}'.format(role_name, member_oid, e))
    #         return False
    #
    # def set_group_owner(self, groupname, owner_id):
    #     """
    #     Set owner for the given group object
    #     Permission type	Permissions (from least to most privileged)
    #     Delegated (work or school account)	Group.ReadWrite.All, Directory.ReadWrite.All, Directory.AccessAsUser.All
    #     Delegated (personal Microsoft account)	Not supported.
    #     Application	Group.ReadWrite.All, Directory.ReadWrite.All
    #     :param groupname: group to update
    #     :param owner_id: samaccountname of the owner to assign
    #     :return:
    #     """
    #     group_obj = self.get_aad_group(groupname=groupname)
    #     if group_obj['value']:
    #         group_oid = group_obj['value'][0]['id']
    #     else:
    #         logad.error('did not get group object for group "{}"'.format(groupname))
    #         return False
    #     user_oid = False
    #     if hasattr(self, 'upn_id_map'):
    #         try:
    #             user_oid = self.upn_id_map[owner_id.lower()]
    #         except KeyError:
    #             logad.warning('User "{}" not found in cache, will try to fetch from Azure AD'.format(owner_id))
    #     else:
    #         logad.warning('No cached user upn id map was found. Will fetch user from Azure AD')
    #
    #     if not user_oid:
    #         user_obj = self.get_aad_user(loginid=owner_id)
    #         if user_obj:
    #             user_oid = user_obj[0]['id']
    #         else:
    #             logad.error('Unable find user object for "{}". Giving up.'.format(owner_id))
    #             return False
    #
    #     raw_headers = {"Authorization": "Bearer " + self.auth['access_token'], "Content-type": "application/json"}
    #     _endpoint = config['apiurl'] + '/groups/{}/owners/$ref'.format(group_oid)
    #
    #     data_dict = {"@odata.id": "https://graph.microsoft.com/v1.0/users/{}".format(user_oid)}
    #     data_json = json.dumps(data_dict)
    #
    #     try:
    #         result = self.session.post(url=_endpoint, headers=raw_headers, data=data_json)
    #         logad.info("Set owner result code: {}".format(result.status_code))
    #
    #     except Exception as e:
    #         logad.error('Exception while making REST call - {}'.format(e))
    #         return False
    #
    # @Timer.add_timer
    # def sync_group_json(self, filename, test=False):
    #     """
    #     Use a json file as input for calling sync_group. file format is adgroup:cldgroup
    #     sample input json file format"
    #     --start--
    #     {
    #         "myadgroup1": "mycloudgroup1",
    #         "myadgroup2": "mycloudgroup2"
    #     }
    #     --end--
    #     :param filename:
    #     :return:
    #     """
    #     if os.path.isfile(filename):
    #         try:
    #             with open(filename) as f:
    #                 logad.info('loading file {}'.format(filename))
    #                 syn_group_dict = json.load(f)
    #                 logad.info('processing groups from sync file..')
    #                 for g in syn_group_dict:
    #                     self.sync_group(adgroup=g, clgroup=syn_group_dict[g], test=test)
    #                 logad.info('finished processing sync file..')
    #
    #         except Exception as e:
    #             logad.error('Exception while loading file. Exception: {}'.format(e))
    #
    #     else:
    #         logad.error('Invalid file path.. "{}"'.format(filename))
    #
    # @Timer.add_timer
    # def sync_group(self, adgroup, clgroup, test=False):
    #     """
    #     Get group members from on-prem AD group and add to a AAD cloud group, and remove members not in on-prem AD group
    #     from cloud group. AD group is retrieved from on-prem ad. requires quest powershell module for ad. On-prem AD group
    #     does not need to be synced to azure ad using AAD sync.
    #     :param adgroup: on prem ad group name
    #     :param clgroup: azure ad cloud group name
    #     :param test: test mode with no writes (bool)
    #     :return:
    #     """
    #
    #     logad.info('Start syncing AD group "{}" to cloud group "{}"'.format(adgroup, clgroup))
    #     if not hasattr(self, 'all_aad_grp_ids'):
    #         self.make_aad_grp_id_map()
    #
    #     if not hasattr(self, 'upn_id_map'):
    #         self.aad_user_upn_map(onprem=True)
    #
    #     adgroup_members = powershell.get_adgroupmember(groupname=adgroup)
    #     if adgroup_members == False:
    #         logad.error('Unable to get on-prem AD group members for "{}". Check group name. Exiting.'.format(adgroup))
    #         return False
    #
    #     self.cldgroup_members_full = self.get_aad_members(groupname=clgroup)
    #
    #     if self.cldgroup_members_full == False:
    #         logad.error('Unable to get Azure AD goup "{}". Check group name. Exiting.'.format(clgroup))
    #         return False
    #
    #     if len(self.cldgroup_members_full['value']) == 0:
    #         is_cldgroup_null = True
    #     else:
    #         is_cldgroup_null = False
    #
    #     cldgroup_members = []
    #
    #     if not is_cldgroup_null:
    #         for user in self.cldgroup_members_full['value']:
    #             cld_upn_short = user['userPrincipalName'].split('@')[0].lower()
    #             cldgroup_members.append(cld_upn_short.lower())
    #
    #     mem_not_in_cld = set(adgroup_members) - set(cldgroup_members)
    #     mem_not_in_ad = set(cldgroup_members) - set(adgroup_members)
    #
    #     logad.info('Members list to be added to cloud group "{}" - {}'.format(clgroup, list(mem_not_in_cld)))
    #
    #     # add missing members to cld group
    #     if mem_not_in_cld:
    #         mem_to_add_to_cld = []
    #         not_in_aad = []
    #
    #         for u in list(mem_not_in_cld):
    #             try:
    #                 mem_to_add_to_cld.append(self.upn_id_map[u.lower()])
    #             except KeyError:
    #                 not_in_aad.append(u)
    #         if not_in_aad:
    #             logad.error(
    #                 'on-prem AD users {} not found in Azure AD. This may be a transient AAD Sync delay.'
    #                 'These users will not be added to group "{}" in this cycle.'.format(not_in_aad, clgroup))
    #
    #         if mem_to_add_to_cld:
    #             logad.info(
    #                 'Adding new members {} to cloud group "{}"'.format(
    #                     list(set(mem_not_in_cld) - set(list(not_in_aad))),
    #                     clgroup))
    #             result = self.add_members_blk(uidlist=mem_to_add_to_cld, gid=self.cldgroup_members_full['group_id'],
    #                                           test=test)
    #             if result:
    #                 logad.info('Bulk add result code: OK')
    #             else:
    #                 logad.error('Bulk add result code: FAILED')
    #     else:
    #         logad.info('No new members to be added to group "{}"'.format(clgroup))
    #
    #     logad.info('Members list to be removed from cloud group "{}" - {}'.format(clgroup, list(mem_not_in_ad)))
    #     if mem_not_in_ad:
    #         logad.info('Deleting members {} from cloud group "{}"'.format(list(mem_not_in_ad), clgroup))
    #         for s_upn in list(mem_not_in_ad):
    #             logad.info('Deleting "{}" from group "{}"'.format(s_upn, clgroup))
    #
    #             try:
    #                 result = self.remove_member(userid=self.upn_id_map[s_upn],
    #                                             gid=self.cldgroup_members_full['group_id'], test=test)
    #                 if test:
    #                     logad.info('Test mode...')
    #                     continue
    #
    #                 logad.info('Status code: {}'.format(result.status_code))
    #
    #             except KeyError:
    #                 logad.error('Unable to find adsynced user {} in azure ad'.format(s_upn))
    #             except Exception as e:
    #                 logad.error(
    #                     'Exception "{}" was thrown while removing id: {} from group: {}'.format(e, s_upn, clgroup))
    #
    #     else:
    #         logad.info('No members need to be removed from cloud group "{}"'.format(clgroup))
    #
    # def add_member(self, userid, gid):
    #     """
    #     Add a single user to a group
    #     :param userid: azure ad user guid
    #     :param gid: azure ad group guid
    #     :return:
    #     """
    #     raw_headers = {"Authorization": "Bearer " + self.auth['access_token'], "Content-type": "application/json",
    #                    "Content-length": "30"}
    #     query_str = '/groups/{}/members/$ref'.format(gid)
    #     _endpoint = config['apiurl'] + query_str
    #
    #     data_dict = {
    #         '@odata.id': config['apiurl'] + '/directoryObjects/{}'.format(userid)
    #     }
    #     data_json = json.dumps(data_dict)
    #     try:
    #         result = self.session.post(url=_endpoint, data=data_json, headers=raw_headers)
    #         return result
    #
    #     except Exception as e:
    #         logad.error('Exception {} while adding users to group "{}"'.format(e, gid))
    #         return False
    #
    # @Timer.add_timer
    # def add_members_blk(self, uidlist, gid, test):
    #     """
    #     Add multiple users to a group. If max number of user is larger than 20, use subsets
    #     :param uidlist:
    #     :param gid:
    #     :return:
    #     """
    #
    #     ret_result = True
    #     if len(uidlist) > 20:
    #         logad.info("Total number of users {} is greater than 20. We'll add in sets of 20".format(len(uidlist)))
    #         while len(uidlist) > 0:
    #             count = 20 if len(uidlist) > 20 else len(uidlist)
    #             uidsubset = [uidlist.pop(0) for n in range(count)]
    #
    #             logad.info('Adding user set {} to group'.format(uidsubset))
    #             result = self.add_mem_blk_sub(uidlist=uidsubset, gid=gid, test=test)
    #
    #             if test:
    #                 logad.info('Test mode...')
    #                 continue
    #
    #             logad.info('Status code:{}'.format(result.status_code))
    #             if result == False: return False
    #             if all([ret_result == True, result.status_code != int(204)]):
    #                 ret_result = False
    #     else:
    #         result = self.add_mem_blk_sub(uidlist=uidlist, gid=gid, test=test)
    #         if test:
    #             logad.info('Test mode...')
    #             return ret_result
    #
    #         logad.info('Status code:{}'.format(result.status_code))
    #         if result == False: return False
    #
    #         if result.status_code != int(204):
    #             logad.error('Status code:{}'.format(result.status_code))
    #             ret_result = False
    #
    #     return ret_result
    #
    # def add_mem_blk_sub(self, uidlist, gid, test):
    #     """
    #     A sub func to add bulk users to a group. This is to handle max 20 member limit in graph api call.
    #     :param uidlist:
    #     :return:
    #     """
    #     raw_headers = {"Authorization": "Bearer " + self.auth['access_token'], "Content-type": "application/json"}
    #     _endpoint = config['apiurl'] + '/groups/{}'.format(gid)
    #
    #     data_dict = {"members@odata.bind": []}
    #
    #     for uid in uidlist:
    #         try:
    #             uid_url = 'https://graph.microsoft.com/v1.0/users/{}'.format(uid)
    #             data_dict["members@odata.bind"].append(uid_url)
    #         except Exception as e:
    #             logad.error('Exception {} in add_members_blk'.format(e))
    #
    #     data_json = json.dumps(data_dict)
    #
    #     if not test:
    #         try:
    #             result = self.session.patch(url=_endpoint, data=data_json, headers=raw_headers)
    #             return result
    #
    #         except Exception as e:
    #             logad.error('Exception while adding users to group "{}"'.format(gid))
    #             return False
    #     else:
    #         logad.info('Running in test mode, no writes performed.')
    #         return None
    #
    # @Timer.add_timer
    # def remove_member(self, userid, gid, test):
    #     """
    #     Remove a user from group
    #     :param userid: azure ad user object id
    #     :param gid: azure ad group object id
    #     :return:
    #     """
    #     raw_headers = {"Authorization": "Bearer " + self.auth['access_token'], "Content-type": "application/json"}
    #     _endpoint = config['apiurl'] + '/groups/{}/members/{}/$ref'.format(gid, userid)
    #
    #     if not test:
    #         try:
    #             result = self.session.delete(url=_endpoint, headers=raw_headers)
    #             return result
    #         except Exception as e:
    #             logad.error('Exception while deleteing user {} from group {}'.format(userid, gid))
    #             return False
    #     else:
    #         logad.info('Running in test mode, no writes performed')
    #         return None
    #
    # def get_open_extensions(self, oid):
    #     """
    #     Get open extensions from user
    #     :param oid:
    #     :return:
    #     """
    #     raw_headers = {"Authorization": "Bearer " + self.auth['access_token'], "Content-type": "application/json"}
    #     _endpoint = config["apiurl"] + "/users/{}/extensions".format(oid)
    #
    #     try:
    #         result = self.session.get(url=_endpoint, headers=raw_headers)
    #         return result.json()
    #
    #     except Exception as e:
    #         logad.error('Exception while making REST call - {}'.format(e))
    #         return False
    #
    # def get_licences_all(self, guid=None):
    #     """
    #     Get a full licence count
    #     :return:
    #     """
    #     raw_headers = {"Authorization": "Bearer " + self.auth['access_token'], "Content-type": "application/json"}
    #     _endpoint = config["apiurl"] + "/subscribedSkus"
    #     if guid:
    #         _endpoint += '/{}'.format(guid)
    #
    #     try:
    #         result = self.session.get(url=_endpoint, headers=raw_headers)
    #         return result.json()
    #     except Exception as e:
    #         logad.error('Exception while making REST call - {}'.format(e))
    #         return False
    #
    # def licence_map(self):
    #     """
    #     Create a licence refernce map with string:guid
    #     :return:
    #     """
    #     lics = self.get_licences_all()
    #     self.lic_map = {}
    #     for l in lics['value']:
    #         self.lic_map[l['skuPartNumber'].lower()] = l['id']
    #
    # def lic_mon(self, skuname, percentage=25, threshold=5):
    #     """
    #     Monitor and report licence thresholds
    #     :param threshold:
    #     :return:
    #     """
    #     if not hasattr(self, 'lic_map'):
    #         self.licence_map()
    #     if skuname.lower() in self.lic_map.keys():
    #         lics = self.get_licences_all(guid=self.lic_map[skuname.lower()])
    #     else:
    #         logad.error('Invalid SKU name, or SKU {} doesnt exist in organization'.format(skuname.upper()))
    #         return False
    #
    #     if lics == False:
    #         loglic.error('Failed to get licence data')
    #         return
    #
    #     free_lics = int(lics['prepaidUnits']['enabled']) - int(lics['consumedUnits'])
    #     used_percentage = (int(lics['consumedUnits']) / int(lics['prepaidUnits']['enabled'])) * 100
    #     free_percentage = round(100 - used_percentage)
    #
    #     if threshold:
    #         if (free_lics) < threshold:
    #             loglic.error("{} Total: {} remaining licence count is {}."
    #                          "Failed free licence threshold of {}.".format(skuname.upper(),
    #                                                                        int(lics['prepaidUnits']['enabled']),
    #                                                                        free_lics,
    #                                                                        threshold))
    #         else:
    #             loglic.info(
    #                 "{} Total: {}. Remaining licence count is {}. Licence status OK".format(skuname.upper(), int(
    #                     lics['prepaidUnits']['enabled']), free_lics))
    #     if percentage:
    #         if (free_percentage) < int(percentage):
    #             loglic.error("{} Total: {}. Free percentage is {}%"
    #                          " Failed free licence threshold of {}%.".format(skuname.upper(),
    #                                                                          int(lics['prepaidUnits']['enabled']),
    #                                                                          free_percentage, percentage))
    #         else:
    #             loglic.info(
    #                 "{} Total: {}. Free percentage {}%. Licence status OK".format(skuname.upper(),
    #                                                                               int(lics['prepaidUnits']['enabled']),
    #                                                                               free_percentage))
    #
    # def get_user_license(self, uid):
    #     """
    #     Get license details for teh given user
    #     :param uid:
    #     :return:
    #     """
    #
    #     raw_headers = {"Authorization": "Bearer " + self.auth['access_token'], "Content-type": "application/json"}
    #     _endpoint = config["apiurl"] + "/users/{}/licenseDetails".format(uid)
    #
    #     try:
    #         result = self.session.get(url=_endpoint, headers=raw_headers)
    #         return result.json()
    #     except Exception as e:
    #         logad.error('Exception while making REST call - {}'.format(e))
    #         return False
    #
    # def report_license_activation(self, outdir):
    #     """
    #     Generate Activation report dict
    #     outpath: p = "\\\\corp.bloomberg.com\\ny-dfs\\Ops\\InfoSys\\Systems Engineering\\Dropboxes\\O365Activations"
    #     :return:
    #     """
    #     raw_headers = {"Authorization": "Bearer " + self.auth['access_token'], "Content-type": "application/json"}
    #     _endpoint = config["apiurl"] + "/reports/getOffice365ActivationsUserDetail"
    #
    #     try:
    #         result = self.session.get(url=_endpoint, headers=raw_headers)
    #         logad.info('Response reason:{} code:{}'.format(result.reason, result.status_code))
    #         raw_l = result.text.splitlines()
    #         raw_l.pop(0)
    #         raw_dict = {}
    #         re_pat = re.compile('".+"')
    #
    #         for i in raw_l:
    #             if re.search(re_pat, i):
    #                 line = re.sub(re_pat, '', i)
    #                 date, upn, disp, p_type, last_act, win, mac, win10m, ios, android, shared = line.split(',')
    #                 disp = re.search(re_pat, i).group()
    #             else:
    #                 date, upn, disp, p_type, last_act, win, mac, win10m, ios, android, shared = i.split(',')
    #
    #             u_o = self.DupObj(upn)
    #             raw_dict[u_o] = {}
    #             raw_dict[u_o]['display_name'] = disp
    #             raw_dict[u_o]['product_type'] = p_type
    #             raw_dict[u_o]['last_activated'] = last_act
    #             raw_dict[u_o]['windows'] = win
    #             raw_dict[u_o]['macos'] = mac
    #             raw_dict[u_o]['win10mobile'] = win10m
    #             raw_dict[u_o]['ios'] = ios
    #             raw_dict[u_o]['android'] = android
    #             raw_dict[u_o]['sharedcomp'] = shared
    #
    #         # write csv file
    #         file_out_lines = []
    #         header = 'Date,User Principal Name,Display Name,Product Type,Last Activated Date,Windows,Mac,' \
    #                  'Windows 10 Mobile,iOS,Android,Activated On Shared Computer'
    #         file_out_lines.append('{}\n'.format(header))
    #
    #         for l in raw_l:
    #             file_out_lines.append('{}\n'.format(l))
    #
    #         epoch_now = str(int((datetime.now()).timestamp()))
    #         fname_csv = 'licact_report.csv'
    #
    #         if os.path.isdir(outdir):
    #             outfile_csv = os.path.join(outdir, fname_csv)
    #
    #             if os.path.isfile(outfile_csv):
    #                 ren_file_name = os.path.join(outdir, 'licact_report_{}.csv'.format(epoch_now))
    #                 logad.info('Renaming old file to {}'.format(ren_file_name))
    #                 os.rename(outfile_csv, ren_file_name)
    #
    #             with open(outfile_csv, 'w') as f:
    #                 logad.info('Writing report file {}'.format(outfile_csv))
    #                 f.writelines(file_out_lines)
    #         else:
    #             logad.error('Destination path "{}" doesnt exist or unreachable'.format(outdir))
    #
    #             # outfile_json = os.path.join(outdir, fname_json)
    #             # with open(outfile_json, 'w') as j:
    #             #     json.dump(raw_dict, j)
    #         return raw_dict
    #
    #     except Exception as e:
    #         logad.error('Exception while making REST call - {}'.format(e))
    #         return False
    #
    # def app_add_cert(self, certfile, keyfile, appid=None):
    #     """
    #     Add a new cert to the application in AAD
    #     :param certfile: new cert file path
    #     :param keyfile: new keyfile path
    #     :return:
    #     """
    #
    #     if all([os.path.isfile(certfile), os.path.isfile(keyfile)]):
    #         data_dict = pfxtopem.rotate_cert(newcert=certfile, newkey=keyfile)
    #         if not data_dict:
    #             logad.error('Unable to get new cert_dict')
    #             return False
    #     else:
    #         logad.error('Unable to find either certfile or keyfile path. Exiting')
    #         return False
    #
    #     if not appid:
    #         app_obj = self.get_app(clientid=config['client_id'])
    #         app_id = app_obj['id']
    #     else:
    #         app_id = appid
    #
    #     raw_headers = {"Authorization": "Bearer " + self.auth['access_token'], "Content-type": "application/json"}
    #     _endpoint = config["apiurl"] + '/applications/{}/addKey'.format(app_id)
    #
    #     data_json = json.dumps(data_dict)
    #
    #     try:
    #         result = self.session.post(url=_endpoint, data=data_json, headers=raw_headers)
    #         if int(result.status_code) == 200:
    #             logad.info('Add cert result code: {}'.format(result.status_code))
    #         else:
    #             logad.error('Add cert result code: {}'.format(result.status_code))
    #         return result
    #
    #     except Exception as e:
    #         logad.error('Exception {} while adding cert to app "{}"'.format(e, config['client_id']))
    #         return False
    #
    # def app_remove_cert(self, certid, appid=None):
    #     """
    #     Remove a given cert from the app
    #     :param certid: id of the cert to remove
    #     :return:
    #     """
    #     if not appid:
    #         app_obj = self.get_app(clientid=config['client_id'])
    #         app_id = app_obj['id']
    #     else:
    #         app_id = appid
    #
    #     raw_headers = {"Authorization": "Bearer " + self.auth['access_token'], "Content-type": "application/json"}
    #     _endpoint = config["apiurl"] + '/applications/{}/removeKey'.format(app_id)
    #
    #     jwt = pfxtopem.get_jwt(keyfile=cert['cert_key_path'])
    #
    #     data_dict = {
    #         "keyId": certid,
    #         "proof": jwt
    #     }
    #
    #     data_json = json.dumps(data_dict)
    #
    #     try:
    #         result = self.session.post(url=_endpoint, data=data_json, headers=raw_headers)
    #         if int(result.status_code) == 204:
    #             logad.info('Remove cert result code: {}'.format(result.status_code))
    #         else:
    #             logad.error('Remove cert result code: {}'.format(result.status_code))
    #         return result
    #
    #     except Exception as e:
    #         logad.error('Exception {} while deleting cert id "{}"'.format(e, certid))
    #         return False
    #
    # def get_app(self, clientid):
    #     """
    #     Get the AAD application reg object
    #     :param app_id:
    #     :return:
    #     """
    #
    #     raw_headers = {"Authorization": "Bearer " + self.auth['access_token'], "Content-type": "application/json"}
    #     _endpoint = config["apiurl"] + '/applications'
    #
    #     try:
    #         result = self.session.get(url=_endpoint, headers=raw_headers)
    #         if int(result.status_code) == 200:
    #             apps = result.json()
    #             for app in apps['value']:
    #                 if app['appId'] == clientid:
    #                     return app
    #
    #             logad.error('Unable to find app reg matching clientid {}'.format(clientid))
    #             return False
    #
    #         else:
    #             logad.error('Get apps result: {}'.format(result.status_code))
    #             return False
    #
    #     except Exception as e:
    #         logad.error('Exception {} while getting app reg object id:"{}"'.format(e, config['app_id']))
    #         return False
    #
    # def rotate_this_cert(self, days=30, force=False):
    #     """
    #     Check the cert used by this app. If it is close to expire, rotate
    #     :param days: Number days remaining in the cert before it is rotated
    #     :return:
    #     """
    #     # Get cert thumb print
    #     this_cert_thumbprint = pfxtopem.cert_thumbprint(cert['cert_path']).upper()
    #
    #     # Get the app object
    #     this_app = self.get_app(config['client_id'])
    #
    #     # Get the expiry for this cert
    #     this_cert = {}
    #     for app_cert in this_app['keyCredentials']:
    #         if app_cert['customKeyIdentifier'] == this_cert_thumbprint:
    #             this_cert = app_cert
    #             break
    #
    #     if not this_cert:
    #         logad.error('Did not find a matching cert in app reg. Exiting')
    #         return
    #
    #     exp_time = datetime.strptime(this_cert['endDateTime'], '%Y-%m-%dT%H:%M:%SZ')
    #     now_time = datetime.now()
    #     diff_time = exp_time - now_time
    #
    #     if not force:
    #         if diff_time.days <= days:
    #             logad.warning('Current cert validity remaining days: {}'.format(diff_time.days))
    #             logad.warning('Current cert will be rotated')
    #         else:
    #             logad.info('Current cert is still valid. Remaining days: {}'.format(diff_time.days))
    #             return
    #     else:
    #         logad.info('Forced cert rotation requested. Will proceed to rotate cert.')
    #
    #     # if close to expire, generate new cert
    #     logad.info('Generating new cert and key files')
    #     cert_dir = os.path.split(cert['cert_path'])[0]
    #     cer_prefix = datetime.strftime(now_time, '%Y%m%d-%H%M%S')
    #     pfxtopem.create_self_signed(cn=this_app['displayName'], destpath=cert_dir)
    #
    #     new_cert_path = os.path.join(cert_dir, this_app['displayName'] + '_cert.pem')
    #     new_key_path = os.path.join(cert_dir, this_app['displayName'] + '_key.pem')
    #
    #     if not all([os.path.isfile(new_cert_path), os.path.isfile(new_key_path)]):
    #         logad.error('Did not find new cert/key generated in path {}'.format(cert_dir))
    #         return
    #
    #     # Add new cert to app
    #     logad.info('Adding the new cert to app client_id:{}'.format(config['client_id']))
    #     resp = self.app_add_cert(certfile=new_cert_path, keyfile=new_key_path, appid=this_app['id'])
    #     if not resp:
    #         logad.error('Failed to add the new cert to app clinet_id:{}. exiting..'.format(config['client_id']))
    #         return
    #
    #     # Rename cert files
    #     logad.info('Renaming cert files..')
    #     bak_cert_fname = cert['cert_path'] + '.' + cer_prefix
    #     bak_key_fname = cert['cert_key_path'] + '.' + cer_prefix
    #     logad.info('Renaming old cert file {} to {}'.format(cert['cert_path'], bak_cert_fname))
    #     os.rename(cert['cert_path'], bak_cert_fname)
    #
    #     logad.info('Renaming old key file {} to {}'.format(cert['cert_key_path'], bak_key_fname))
    #     os.rename(cert['cert_key_path'], bak_key_fname)
    #
    #     logad.info('Renaming new cert file {} to {}'.format(new_cert_path, cert['cert_path']))
    #     os.rename(new_cert_path, cert['cert_path'])
    #
    #     logad.info('Renaming new key file {} to {}'.format(new_key_path, cert['cert_key_path']))
    #     os.rename(new_key_path, cert['cert_key_path'])
    #
    #     # remove old cert from app
    #     logad.info('Removing old cert keyid {} from app client_id:{}'.format(this_cert['keyId'], config['client_id']))
    #     resp = self.app_remove_cert(certid=this_cert['keyId'], appid=this_app['id'])
    #     if not resp:
    #         logad.error('Removing cert failed..')
    #     elif int(resp.status_code) == 204:
    #         logad.info('Successfully deleted old cert keyid:{} from app client_id:{}'.format(this_cert['keyId'],
    #                                                                                       config['client_id']))
    #     else:
    #         logad.error('Removing old cert failed with status code {}'.format(resp.status_code))
