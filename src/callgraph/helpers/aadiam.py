import time
import json
import os
import sys
import platform
import re
import functools
import timeit
import traceback

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from callgraph.helpers import my_logger
from callgraph.helpers.config import config
from callgraph.helpers import powershell
from callgraph.helpers.azureauth import AzureAd
from callgraph.helpers import com_utils

if platform.system().lower() == 'windows':
    LOG_DIR = os.path.join('c:\\', 'logs', 'azgraph')
else:
    LOG_DIR = os.path.join(os.environ['VIRTUAL_ENV'], 'logs', 'azgraph')

logad = my_logger.My_logger(logdir=LOG_DIR, logfile='azureiam')
loglic = my_logger.My_logger(logdir=LOG_DIR, logfile='licence')


class Aadiam(AzureAd):
    """
    Azure AD User and Groups management methods
    """

    def __init__(self, cert_auth=True, auto_rotate=False, days=30):
        super(Aadiam, self).__init__(cert_auth=cert_auth, auto_rotate=auto_rotate, days=days)

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
                logad.info(
                    "Function {} - Elapsed time: {}".format(
                        func.__name__, round(elapsed_time, 3)
                    )
                )
                return func_results

            return timed_func

    def get_aad_user(self, displayname=None, loginid=None, onprem=False):
        """
        Search for a user by displayname. This is a wildcard search.
        :param displayname: display name
        :param loginid: samaccountname
        :param onprem: get only on prem synced accounts, if False return both on-prem and cloud objects
        :return:
        """

        raw_headers = {"Authorization": "Bearer " + self.auth['access_token'], "ConsistencyLevel": "eventual"}

        filter_suffix = "$top=999&$select=onPremisesSyncEnabled,id,userPrincipalName,businessPhones,displayName,givenName," \
                        "jobTitle,mail,mobilePhone,officeLocation,surname"

        if displayname:
            query_str = "?$filter=displayName eq '{}'".format(displayname)
        elif loginid:
            # If loginid doesnt contain @ append @, else pass loginid as is for filter
            if not re.match('([a-zA-Z0-9]+@)', loginid):
                loginid += '@'
            query_str = f"?$filter=startswith(userPrincipalname, '{loginid}')"

        else:
            # Get all users
            query_str = "?"

        page = True
        allusers_full = []
        _endpoint = config["apiurl"] + "/users" + query_str + "&" + filter_suffix

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
            logad.error('Exception while getting group from AAD - {}'.format(e))
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
                    logad.error('Error while getting group members for "{}" - {}'.format(group_obj, e))
                    page = False

            return ret_dict

        elif not group_obj:
            logad.error('Did not get Azure AD group. API call failed with exception')
            return False

        elif not group_obj['value']:
            logad.error(f'Did not get an Azure AD group object "{groupname}"')
            return "noobj"

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
            logad.error('Failed to get users list from AAD')
            return False

    def get_aad_roles_templates(self):
        """
        Get all AAD roles templates
        :return:
        """
        raw_headers = {"Authorization": "Bearer " + self.auth['access_token']}
        _endpoint = config["apiurl"] + "/directoryRoleTemplates"

        try:
            result = self.session.get(url=_endpoint, headers=raw_headers)
            if result.status_code == 200:
                return result.json()
            else:
                logad.error('Error while getting roles templates')
                logad.error('Status code: {}'.format(result.status_code))
                return False


        except Exception as e:
            logad.error('Exception while making API call - {}'.format(e))

    def get_aad_roles_active(self):
        """
        Get a list all active Azure Ad roles
        :return:
        """
        raw_headers = {"Authorization": "Bearer " + self.auth['access_token']}
        _endpoint = config["apiurl"] + "/directoryRoles"

        try:
            result = self.session.get(url=_endpoint, headers=raw_headers)
            if result.status_code == 200:
                return result.json()
            else:
                logad.error('Error while getting roles')
                logad.error(f'Status code: {result.status_code}')
                return False


        except Exception as e:
            logad.error(f'Exception while making API call - {e}')

    def get_pim_eligibility_assignments(self):
        """
        Get a list PIM eligibility assignments for AD roles
        :return:
        """
        raw_headers = {"Authorization": "Bearer " + self.auth['access_token']}
        _endpoint = config["apibetaurl"] + "/roleManagement/directory/roleEligibilityScheduleInstances"

        page = True

        try:
            eligible_assigns = []
            while page:
                result = self.session.get(url=_endpoint, headers=raw_headers)

                if result.status_code == 200:
                    result_json = result.json()
                    eligible_assigns.extend(result_json['value'])
                    if '@odata.nextLink' in result_json.keys():
                        _endpoint = result_json['@odata.nextLink']
                    else:
                        page = False

                else:
                    logad.error('Error while getting assignments')
                    logad.error(f'Status code: {result.status_code}')
                    return False

            return eligible_assigns


        except Exception as e:
            logad.error(f'Exception while making API call - {e}')
            traceback.print_exc()

    def get_pim_assignment_schedule(self):
        """
        Get a list of role assignment schedules for role members. These are active assignments in PIM role
        :return:
        """
        raw_headers = {"Authorization": "Bearer " + self.auth['access_token']}
        _endpoint = config["apibetaurl"] + "/roleManagement/directory/roleAssignmentSchedules"

        page = True

        try:
            active_assigns = []
            while page:
                result = self.session.get(url=_endpoint, headers=raw_headers)

                if result.status_code == 200:
                    result_json = result.json()
                    active_assigns.extend(result_json['value'])
                    if '@odata.nextLink' in result_json.keys():
                        _endpoint = result_json['@odata.nextLink']
                    else:
                        page = False

                else:
                    logad.error('Error while getting assignments')
                    logad.error(f'Status code: {result.status_code}')
                    return False

            return active_assigns

        except Exception as e:
            logad.error(f'Exception while making API call - {e}')

    def make_aad_roles_map(self):
        """
        Generate a dict of roles {display name: id}
        :return:
        """
        roles = self.get_aad_roles_templates()
        self.aad_roles_map = {}
        self.aad_roles_map_rev = {}
        if roles['value']:
            for role in roles['value']:
                self.aad_roles_map[role['displayName'].lower()] = role['id']
                self.aad_roles_map_rev[role['id']] = role['displayName'].lower()

        else:
            logad.error('Unable to get roles from aad. Giving up.')
            return False

    def create_aad_group(self, groupname, role_enable=True, gtype=None, assign_role=None):
        """
        Create an Azure AD group
        :param groupname: group name
        :param gtype: type of group to create
        :return:
        """
        raw_headers = {"Authorization": "Bearer " + self.auth['access_token'], "Content-type": "application/json"}
        _endpoint = config["apiurl"] + "/groups"

        if gtype == 365 or gtype == "365":
            group_type = ['Unified']
            mail_enabled = True
        else:
            group_type = []
            mail_enabled = False

        data_dict = {
            'displayName': groupname,
            'description': 'Created by API',
            'isAssignableToRole': role_enable,
            'mailEnabled': mail_enabled,
            'mailNickname': groupname,
            'securityEnabled': True,
            'groupTypes': group_type,
            'visibility': 'Private'
        }

        data_json = json.dumps(data_dict)

        # Check if name is in use. This is to handle a bug in API that creates duplicate groups with same name.
        try:
            chk_grp = self.get_aad_group(groupname=groupname)
            if chk_grp['value']:
                logad.error(f'Error while creating group. Name "{groupname}" already exists. Exiting..')
                return False

        except Exception as e:
            logad.error(f'Exception while checking for group object - {e}. Exiting..')
            return False

        logad.info(f'Creating Azure AD group name={groupname}, gtype={gtype}, role_enable={role_enable}, '
                   f'assign_role={assign_role}')
        try:
            resp = self.session.post(url=_endpoint, headers=raw_headers, data=data_json)

            if all([role_enable, assign_role]):
                logad.info('Assigning role {} to group {}'.format(assign_role, groupname))
                group_oid = None
                timeout = False
                count = 0
                while all([not group_oid, not timeout]):
                    try:
                        group_obj = self.get_aad_group(groupname=groupname)
                        group_oid = group_obj['value'][0]['id']
                        resp_add_role = self.add_member_to_role(member_oid=group_oid, role_name=assign_role)
                        logad.info('Add group to role response: {}'.format(resp_add_role))
                    except Exception as e:
                        if count == 5:
                            timeout = True
                            logad.error('Timeout reached. Unable to get group object. Exiting')
                            continue
                        logad.info('Waiting 5 seconds before retrying..')
                        count += 1
                        time.sleep(5)

            return resp
        except Exception as e:
            logad.error('Exception was throws while creating group {}, - {}'.format(groupname, e))

    def add_member_to_role(self, member_oid, role_name):
        """
        Add a given object ID to a AAD Role
        :param member_oid: object ID of user/group
        :param role_name: template name of the role, such as "global readers" etc
        :return:
        """
        if not hasattr(self, 'aad_roles_map'):
            self.make_aad_roles_map()

        if self.aad_roles_map.get(role_name.lower()):
            role_template_id = self.aad_roles_map[role_name.lower()]
        else:
            logad.error('Unable to find template id for role "{}"'.format(role_name))
            return False

        raw_headers = {"Authorization": "Bearer " + self.auth['access_token'], "Content-type": "application/json"}
        _endpoint = config["apiurl"] + "/directoryRoles/roleTemplateId={}/members/$ref".format(role_template_id)

        data_dict = {
            "@odata.id": "https://graph.microsoft.com/v1.0/directoryObjects/{}".format(member_oid)
        }
        data_json = json.dumps(data_dict)

        try:
            resp = self.session.post(url=_endpoint, headers=raw_headers, data=data_json)
            if resp.status_code == int(204):
                logad.info('Status code: {}'.format(resp.status_code))
                return
            else:
                logad.error('Status code: {}'.format(resp.status_code))
                return resp.json()
        except Exception as e:
            logad.error(
                'Exception was thrown while assigning role "{}" to object "{}" - {}'.format(role_name, member_oid, e))
            return False

    def set_group_owner(self, groupname, owner_id):
        """
        Set owner for the given group object
        Permission type	Permissions (from least to most privileged)
        Delegated (work or school account)	Group.ReadWrite.All, Directory.ReadWrite.All, Directory.AccessAsUser.All
        Delegated (personal Microsoft account)	Not supported.
        Application	Group.ReadWrite.All, Directory.ReadWrite.All
        :param groupname: group to update
        :param owner_id: samaccountname of the owner to assign
        :return:
        """
        group_obj = self.get_aad_group(groupname=groupname)
        if group_obj['value']:
            group_oid = group_obj['value'][0]['id']
        else:
            logad.error('did not get group object for group "{}"'.format(groupname))
            return False

        user_oid = self.get_upn_uid(owner_id)
        if not user_oid:
            logad.error(f"Unable to get UID for user '{owner_id}'")
            return False

        raw_headers = {"Authorization": "Bearer " + self.auth['access_token'], "Content-type": "application/json"}
        _endpoint = config['apiurl'] + '/groups/{}/owners/$ref'.format(group_oid)

        data_dict = {"@odata.id": "https://graph.microsoft.com/v1.0/users/{}".format(user_oid)}
        data_json = json.dumps(data_dict)

        try:
            result = self.session.post(url=_endpoint, headers=raw_headers, data=data_json)

            if int(result.status_code) == 204:
                logad.info(f"Set owner result code: {result.status_code}")
                # logad.info("Sleep 30 secs for propogation")
                # time.sleep(30)
                return True
            else:
                logad.error(f"Set owner result code: {result.status_code}")
                return False

        except Exception as e:
            logad.error(f'Exception while making REST call - {e}')
            return False

    def get_upn_uid(self, owner_id):
        """
        Get the UID for a given user object
        :param owner_id: samaccountname of the user
        :return:
        """
        user_oid = False
        if hasattr(self, 'upn_id_map'):
            try:
                user_oid = self.upn_id_map[owner_id.lower()]
                return user_oid
            except KeyError:
                logad.warning('User "{}" not found in cache, will try to fetch from Azure AD'.format(owner_id))
        else:
            logad.warning('No cached user upn id map was found. Will fetch user from Azure AD')

        if not user_oid:
            user_obj = self.get_aad_user(loginid=owner_id)
            if user_obj:
                user_oid = user_obj[0]['id']
                return user_oid
            else:
                logad.error('Unable find user object for "{}". Giving up.'.format(owner_id))
                return False

    def get_group_owner(self, groupname):
        """
        Return teh owner for the given groupname object
        :param groupname:
        :return:
        """
        grp_obj = self.get_aad_group(groupname)

        if not grp_obj['value']:
            logad.error(f"Did not find group object for '{groupname}' in Azure AD. Exiting")
            return False

        raw_headers = {"Authorization": "Bearer " + self.auth['access_token'], "Content-type": "application/json"}
        _endpoint = config['apiurl'] + f"/groups/{grp_obj['value'][0]['id']}/owners/"

        try:
            result = self.session.get(url=_endpoint, headers=raw_headers)
            return result

        except Exception as e:
            logad.error(f'Exception while making REST call - {e}')
            return False

    @Timer.add_timer
    def sync_group_json(self, filename, test=False, create=False):
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
        :param test: Test mode with no writes
        :param create: Create target group if missing in Azure AD
        :return:
        """
        logad.title("Starting group sync using JSON file")
        if os.path.isfile(filename):
            try:
                with open(filename) as f:
                    logad.info('loading file {}'.format(filename))
                    sync_group_dict = json.load(f)
                    logad.info('processing groups from sync file..')
                    self.json_sync_proc(sync_group_dict, test=test, create=create)
                    # for g in syn_group_dict:
                    #     self.sync_group(adgroup=g, clgroup=syn_group_dict[g], test=test, create=create)
                    logad.info('finished processing sync file..')

            except Exception as e:
                logad.error('Exception while loading file. Exception: {}'.format(e))

        else:
            logad.error('Invalid file path.. "{}"'.format(filename))

    @Timer.add_timer
    def sync_group_git(self, repo, filepath, token, git_url=None, branch='master', test=False, create=False):
        """
        Use a json file as input for calling sync_group. file format is adgroup:cldgroup
        sample input json file format. The file is pulled from a git repo."
        --start--
        {
            "myadgroup1": "mycloudgroup1",
            "myadgroup2": "mycloudgroup2"
        }
        --end--
        :param repo: git repo name
        :param filepath:
        :param token:
        :param branch:
        :param test: Test mode with no writes
        :param create: Create target group if missing in Azure AD
        :return:
        """
        logad.title("Starting group sync using git repo")
        if git_url:
            base_url = git_url
        else:
            try:
                base_url = config['github_url']
                logad.info(f'Git base url in config: {base_url}')
            except:
                logad.info('No git url was specified. Defaulting to https://api.github.com')
                base_url = 'https://api.github.com'

        try:
            logad.info(f'Fetching file from git url: {base_url} repo: {repo}, filepath: {filepath}')
            git_file = com_utils.github_get_file(base_url=base_url, repo=repo, path=filepath, git_token=token,
                                                 branch=branch)
            if git_file:
                logad.info('processing groups from sync file (git repo)..')
                sync_group_dict = json.loads(git_file.read())
                self.json_sync_proc(sync_group_dict, test=test, create=create)
                # for g in sync_group_dict:
                #     self.sync_group(adgroup=g, clgroup=sync_group_dict[g], test=test, create=create)
                logad.info('finished processing sync file (git repo)..')

        except Exception as e:
            logad.error(f'Exception was thrown while getting file from github repo - {e}')

    def json_sync_proc(self, json_file_dict, test=False, create=False):
        """
        This function will run the group sync for teh given JSON file. This method will support both filesystem file
        as well as github file. The common parsing for both modes are consolidated here to minimize code repetition.
        :param json_file_dict:
        :param test: Run in test mode with no writes
        :param create: Create target group in Azure AD if doesnt exist
        :return:
        """
        if isinstance(json_file_dict, dict):
            # check if file is new type or legacy
            if set(json_file_dict.keys()) & {'security', '365'} == {'security', '365'}:
                # new type
                logad.info("Detected new input file schema type.")
                if 'role_enable' in json_file_dict.keys():
                    if isinstance(json_file_dict['role_enable'], bool):
                        role_enable = json_file_dict['role_enable']
                        logad.info(f"role_enable = {role_enable}")
                    else:
                        logad.warning("Fallback (invalid key value, using default) role_enable=True")
                        role_enable = True
                else:
                    logad.warning("Fallback (no key found, using default), role_enable=True")
                    role_enable = True

                for sg in json_file_dict['security'].keys():
                    self.sync_group(adgroup=sg, clgroup=json_file_dict['security'][sg], test=test, create=create,
                                    gtype='', role_enable=role_enable)

                for og in json_file_dict['365'].keys():
                    self.sync_group(adgroup=og, clgroup=json_file_dict['365'][og], test=test, create=create,
                                    gtype='365', role_enable=role_enable)

            else:
                # legacy type
                logad.info("Detected legacy input file schema type.")
                for g in json_file_dict.keys():
                    self.sync_group(adgroup=g, clgroup=json_file_dict[g], test=test, create=create,
                                    gtype='', role_enable=True)

        else:
            logad.error("Invalid arg type given to json_sync_proc, expected dict.")
            return False

    @Timer.add_timer
    def sync_group(self, adgroup, clgroup, test=False, create=False, gtype='', role_enable=True):
        """
        Get group members from on-prem AD group and add to a AAD cloud group, and remove members not in on-prem AD group
        from cloud group. AD group is retrieved from on-prem ad. requires quest powershell module for ad. On-prem AD group
        does not need to be synced to azure ad using AAD sync.
        :param adgroup: on prem ad group name
        :param clgroup: azure ad cloud group name
        :param test: test mode with no writes (bool)
        :param create: Create target group if doesnt exist (bool)
        :param gtype: target group type to create, one of 365 (m365) or None (security)
        :param role_enable: role enable teh target group during creation (bool)
        :return:
        """
        try:
            if not gtype:
                g_type = "Security"
            elif gtype == 365 or gtype == "365":
                g_type = "365"
            else:
                logad.error(f"Invalid gtype'{gtype}'. Must be either None|365.")
                return False

            logad.info('Start syncing AD group "{}" to cloud group "{}", type "{}"'.format(adgroup, clgroup, g_type))
            if not hasattr(self, 'all_aad_grp_ids'):
                self.make_aad_grp_id_map()

            if not hasattr(self, 'upn_id_map'):
                self.aad_user_upn_map(onprem=True)

            adgroup_members = powershell.get_adgroupmember(groupname=adgroup)
            if adgroup_members == False:
                logad.error(
                    'Unable to get on-prem AD group members for "{}". Check group name. Exiting.'.format(adgroup))
                return False

            self.cldgroup_members_full = self.get_aad_members(groupname=clgroup)

            if self.cldgroup_members_full == False:
                logad.error(f'Unable to get Azure AD group "{clgroup}". API call failed. Exiting.')
                return False
            elif self.cldgroup_members_full == 'noobj':
                logad.error(f'Unable to find group object "{clgroup}" in Azure AD')
                if create:
                    logad.warning(f'Target Azure AD group "{clgroup}" doesnt exist. Will auto create new group.')
                    if not test:
                        result = self.create_target_group(groupname=clgroup, role_enable=role_enable, gtype=g_type)
                        if not result:
                            logad.error('Creating target group failed. Exiting..')
                            return False
                    else:
                        logad.info("Test mode. Group not created..")
                        return False
                else:
                    logad.error(f'Auto target group creation is "False". Skipping sync for group "{clgroup}"')
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

            logad.info('Members list to be added to cloud group "{}" - {}'.format(clgroup, list(mem_not_in_cld)))

            # add missing members to cld group
            if mem_not_in_cld:
                mem_to_add_to_cld = []
                not_in_aad = []

                for u in list(mem_not_in_cld):
                    try:
                        mem_to_add_to_cld.append(self.upn_id_map[u.lower()])
                    except KeyError:
                        not_in_aad.append(u)
                if not_in_aad:
                    logad.error(
                        'on-prem AD users {} not found in Azure AD. This may be a transient AAD Sync delay.'
                        'These users will not be added to group "{}" in this cycle.'.format(not_in_aad, clgroup))

                if mem_to_add_to_cld:
                    logad.info(
                        'Adding new members {} to cloud group "{}"'.format(
                            list(set(mem_not_in_cld) - set(list(not_in_aad))),
                            clgroup))
                    result = self.add_members_blk(uidlist=mem_to_add_to_cld, gid=self.cldgroup_members_full['group_id'],
                                                  test=test)
                    if result:
                        logad.info('Bulk add result code: OK')
                    else:
                        logad.error('Bulk add result code: FAILED')
            else:
                logad.info('No new members to be added to group "{}"'.format(clgroup))

            logad.info('Members list to be removed from cloud group "{}" - {}'.format(clgroup, list(mem_not_in_ad)))
            if mem_not_in_ad:
                logad.info('Deleting members {} from cloud group "{}"'.format(list(mem_not_in_ad), clgroup))
                for s_upn in list(mem_not_in_ad):
                    logad.info('Deleting "{}" from group "{}"'.format(s_upn, clgroup))

                    try:
                        result = self.remove_member(userid=self.upn_id_map[s_upn],
                                                    gid=self.cldgroup_members_full['group_id'], test=test)
                        if test:
                            logad.info('Test mode...')
                            continue

                        logad.info('Status code: {}'.format(result.status_code))

                    except KeyError:
                        logad.error('Unable to find adsynced user {} in azure ad'.format(s_upn))
                    except Exception as e:
                        logad.error(
                            'Exception "{}" was thrown while removing id: {} from group: {}'.format(e, s_upn, clgroup))

            else:
                logad.info('No members need to be removed from cloud group "{}"'.format(clgroup))
        except Exception as e:
            logad.error(f"Exception while syncing group - {e}")
            traceback.print_exc()
            return False

    def create_target_group(self, groupname, role_enable, gtype=None):
        """
        This method will auto create teh target cloud group during sync, if the target group is missing in Azure AD.
        The created group will be a role enabled security group
        :param groupname: group name to create in Azure AD
        :return:
        """
        result = self.create_aad_group(groupname=groupname, role_enable=role_enable, gtype=gtype)
        if result:
            if int(result.status_code) == 201:
                count = 0
                while count <= 4:
                    logad.info('Waiting 15 sec for Azure AD convergance')
                    time.sleep(15)
                    mems = self.get_aad_members(groupname=groupname)
                    if any([mems == 'noobj', mems == False]):
                        count += 1
                        continue
                    else:
                        self.cldgroup_members_full = mems
                        logad.info(f'Successfully created new role enabled Azure AD security group "{groupname}"')
                        return True
                logad.error('Unable to get new group object after 60 seconds. Exiting..')
                return False
        else:
            logad.error('Error while creating target group. Upstream method call failed.')
            return False

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
            logad.error('Exception {} while adding users to group "{}"'.format(e, gid))
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
            logad.info("Total number of users {} is greater than 20. We'll add in sets of 20".format(len(uidlist)))
            while len(uidlist) > 0:
                count = 20 if len(uidlist) > 20 else len(uidlist)
                uidsubset = [uidlist.pop(0) for n in range(count)]

                logad.info('Adding user set {} to group'.format(uidsubset))
                result = self.add_mem_blk_sub(uidlist=uidsubset, gid=gid, test=test)

                if test:
                    logad.info('Test mode...')
                    continue

                logad.info('Status code:{}'.format(result.status_code))
                if result == False: return False
                if all([ret_result == True, result.status_code != int(204)]):
                    ret_result = False
        else:
            result = self.add_mem_blk_sub(uidlist=uidlist, gid=gid, test=test)
            if test:
                logad.info('Test mode...')
                return ret_result

            logad.info('Status code:{}'.format(result.status_code))
            if result == False: return False

            if result.status_code != int(204):
                logad.error('Status code:{}'.format(result.status_code))
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
                logad.error('Exception {} in add_members_blk'.format(e))

        data_json = json.dumps(data_dict)

        if not test:
            try:
                result = self.session.patch(url=_endpoint, data=data_json, headers=raw_headers)
                return result

            except Exception as e:
                logad.error('Exception while adding users to group "{}"'.format(gid))
                return False
        else:
            logad.info('Running in test mode, no writes performed.')
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
                logad.error('Exception while deleteing user {} from group {}'.format(userid, gid))
                return False
        else:
            logad.info('Running in test mode, no writes performed')
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
            logad.error('Exception while making REST call - {}'.format(e))
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
            logad.error('Exception while making REST call - {}'.format(e))
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
            logad.error('Invalid SKU name, or SKU {} doesnt exist in organization'.format(skuname.upper()))
            return False

        if lics == False:
            loglic.error('Failed to get licence data')
            return

        free_lics = int(lics['prepaidUnits']['enabled']) - int(lics['consumedUnits'])
        used_percentage = (int(lics['consumedUnits']) / int(lics['prepaidUnits']['enabled'])) * 100
        free_percentage = round(100 - used_percentage)

        if threshold:
            if (free_lics) < threshold:
                loglic.error("{} Total: {} remaining licence count is {}."
                             "Failed free licence threshold of {}.".format(skuname.upper(),
                                                                           int(lics['prepaidUnits']['enabled']),
                                                                           free_lics,
                                                                           threshold))
            else:
                loglic.info(
                    "{} Total: {}. Remaining licence count is {}. Licence status OK".format(skuname.upper(), int(
                        lics['prepaidUnits']['enabled']), free_lics))
        if percentage:
            if (free_percentage) < int(percentage):
                loglic.error("{} Total: {}. Free percentage is {}%"
                             " Failed free licence threshold of {}%.".format(skuname.upper(),
                                                                             int(lics['prepaidUnits']['enabled']),
                                                                             free_percentage, percentage))
            else:
                loglic.info(
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
            logad.error('Exception while making REST call - {}'.format(e))
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
            logad.info('Response reason:{} code:{}'.format(result.reason, result.status_code))
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

            fname_csv = 'licact_report.csv'

            com_utils.write_out_file(outdir=outdir, filename=fname_csv, outlines=file_out_lines)

        except Exception as e:
            logad.error('Exception while making REST call - {}'.format(e))
            return False

    def report_onedrive_usage(self, outdir):
        """
        Generate onedrive usage  report
        outpath: p = "\\\\corp.bloomberg.com\\ny-dfs\\Ops\\InfoSys\\Systems Engineering\\Dropboxes\\O365Activations"
        :return:
        """
        raw_headers = {"Authorization": "Bearer " + self.auth['access_token'], "Content-type": "application/json"}
        _endpoint = config["apiurl"] + "/reports/getOneDriveUsageAccountDetail(period='D7')"

        try:
            result = self.session.get(url=_endpoint, headers=raw_headers)
            logad.info('Response reason:{} code:{}'.format(result.reason, result.status_code))

            raw_l = result.text.splitlines()
            raw_l.pop(0)

            header = "date,site_url,display_name,is_deleted,last_activity,file_count,actice_f_count,used_bytes,alloc_bytes,upn,period"

            out_lines = []
            out_lines.append(f"{header}\n")
            for line in raw_l:
                out_lines.append(f"{line}\n")

            fname = 'odb_usage_report.csv'

            com_utils.write_out_file(outdir=outdir, filename=fname, outlines=out_lines)

        except Exception as e:
            logad.error('Exception while making REST call - {}'.format(e))
            return False

    def report_office_usage(self, outdir):
        """
        Generate office apps usage  report
        outpath: p = "\\\\corp.bloomberg.com\\ny-dfs\\Ops\\InfoSys\\Systems Engineering\\Dropboxes\\O365Activations"
        :return:
        """
        # BETA
        raw_headers = {"Authorization": "Bearer " + self.auth['access_token'], "Content-type": "application/json"}
        _endpoint = config["apibetaurl"] + "/reports/getM365AppUserDetail(period='D7')/content?$format=text/csv"

        try:
            result = self.session.get(url=_endpoint, headers=raw_headers)
            logad.info('Response reason:{} code:{}'.format(result.reason, result.status_code))

            raw_l = result.text.splitlines()
            out_lines = []
            for line in raw_l:
                out_lines.append(f'{line}\n')

            fname = 'office_usage_report.csv'

            com_utils.write_out_file(outdir=outdir, filename=fname, outlines=out_lines)

        except Exception as e:
            logad.error('Exception while making REST call - {}'.format(e))
            return False

    def revoke_session(self, userid):
        """
        revoke all sessions for the given user id
        :param usserid: user object id or upn
        :return:
        """

        raw_headers = {"Authorization": "Bearer " + self.auth['access_token'], "Content-type": "application/json"}
        _endpoint = config["apiurl"] + "/users/{}/revokeSignInSessions".format(userid)

        try:
            logad.info('Revoking sessions for user : {}'.format(userid))
            result = self.session.post(url=_endpoint, headers=raw_headers)
            if int(result.status_code) == 200:
                logad.info('Successfully revoked session')
            else:
                logad.error('Status code: {}'.format(result.status_code))
            return result.json()
        except Exception as e:
            logad.error('Exception while making REST call - {}'.format(e))
            return False

    def revoke_sessions_blk(self, filename):
        """
        Revoke multiple user sessions for id in given input file
        :param filename: File withe object IDs or upns, one per line in CSV format
        :return:
        """
        if os.path.isfile(filename):
            with open(filename) as f:
                lines = f.readlines()
                for line in lines:
                    self.revoke_session(userid=line.strip())
        else:
            logad.error('Invalid file path or input file not found')
