import json
import platform
import os
import re

from callgraph.helpers.aadiam import Aadiam
from callgraph.helpers import my_logger
from callgraph.helpers import com_utils
from callgraph.helpers.config import config
from callgraph.helpers.config import tenancy

if platform.system().lower() == 'windows':
    LOG_DIR = os.path.join('c:\\', 'logs', 'azgraph')
else:
    LOG_DIR = os.path.join(os.environ['VIRTUAL_ENV'], 'logs', 'azgraph')

logteams = my_logger.My_logger(logdir=LOG_DIR, logfile='teams')


class Teams(Aadiam):
    def __init__(self, cert_auth=True, auto_rotate=False, days=30):
        super(Aadiam, self).__init__(cert_auth=cert_auth, auto_rotate=auto_rotate, days=days)
        self.make_aad_roles_map()

    def create_team_from_group(self, groupname, owner=None):
        """
        Create a team for an existing group
        :param groupname:
        :param owner: owner samaccountname
        :return:
        """
        # Check if group exists
        grp_obj = self.get_aad_group(groupname)
        if grp_obj['value']:
            logteams.info(f'{groupname} group object exists. Validating.')
            if all([grp_obj['value'][0]['groupTypes'] == ['Unified'],
                    grp_obj['value'][0]['isAssignableToRole'] == False]):
                logteams.info(f'{groupname} is type m365, and is not role enabled. Will proceed.')
                grp_id = grp_obj['value'][0]['id']
                # proceed with enabling TEAMS

            else:
                logteams.error(f'{groupname} is either not of type 365, or is role enable. Wont proceed.')
                return False
        else:
            logteams.error(f'{groupname} group object not found in Azure AD. Wont proceed.')
            return False

        #enable TEAMS for group
        raw_headers = {"Authorization": "Bearer " + self.auth['access_token'], "Content-type": "application/json"}

        _endpoint = config["apiurl"] + "/teams"

        data_dict = {
            "template@odata.bind": "https://graph.microsoft.com/v1.0/teamsTemplates('standard')",
            "group@odata.bind": f"https://graph.microsoft.com/v1.0/groups('{grp_id}')"
        }

        data_json = json.dumps(data_dict)

        try:
            logteams.info(f"Creating a new TEAMS site for '{groupname}'")
            result = self.session.post(url=_endpoint, data=data_json, headers=raw_headers)

            if int(result.status_code) == 202:
                logteams.info(f"Successfully created a new TEAMS for '{groupname}'")

                if owner:
                    logteams.info(f"Setting owner '{owner}' for '{groupname}'")
                    owner_r = self.set_group_owner(groupname, owner_id=owner)
                    if owner_r:
                        return True
                    else:
                        return False
            else:
                logteams.error(f"Enabling TEAMS for '{groupname}' failed with status {result.status_code}")
                logteams.error(f"{result.json()}")
                return False

        except Exception as e:
            logteams.error(f"REST API call to create TEAMS failed with exception - {e}")
            return False


    def get_teams(self, groupname):
        """
        Check if a TEAMS site exists for a given groupname
        :param groupname:
        :return:
        """
        # Get group
        grp_obj = self.get_aad_group(groupname)
        if not grp_obj['value']:
            logteams.error(f"Group object '{groupname} not found in Azure AD")
            return False

        raw_headers = {"Authorization": "Bearer " + self.auth['access_token'], "Content-type": "application/json"}
        _endpoint = config["apiurl"] + f"/teams/{grp_obj['value'][0]['id']}"

        try:
            result = self.session.get(url=_endpoint, headers=raw_headers)
            return result
        except Exception as e:
            logteams.error(f"REST API call to get TEAMS failed with Exception - '{e}'")
            return False


    def new_teams(self, groupname, owner=None):
        """
        create a new TEAMS for the groupname, set owner. If the TEAMS already exists, verify the owner is set correctly.
        :param groupname:
        :param owner:
        :return:
        """
        # check if a teams site exists for the group first
        pre_check = self.get_teams(groupname)
        if pre_check:
            if int(pre_check.status_code) == 200:
                logteams.info(f"A TEAMS site already exists for group '{groupname}")
                site_found = True
            else:
                site_found = False

        else:
            logteams.error("Pre-check to check TEAMS failed")
            return False

        if not site_found:
            result = self.create_team_from_group(groupname, owner=owner)
            if not result:
                logteams.error(f"Failed to create TEAMS site for '{groupname}'")

        else:
            logteams.info(f"VErifying owner for group '{groupname}'")
            g_owner = self.get_group_owner(groupname)







