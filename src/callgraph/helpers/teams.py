import json
import platform
import os
import re
import time
from time import sleep

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

    def create_team_from_group(self, groupname, owner, creategroup=False):
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
        elif creategroup:
            logteams.warning(f"Group '{groupname}' does not exist. Creating new group.")
            g_o, status = self.new_365_group(groupname)
            if not status:
                return False
            else:
                grp_id = g_o['value'][0]['id']

        else:
            logteams.error(f'{groupname} group object not found in Azure AD. Wont proceed.')
            return False

        # enable TEAMS for group
        raw_headers = {"Authorization": "Bearer " + self.auth['access_token'], "Content-type": "application/json"}

        _endpoint = config["apiurl"] + "/teams"

        data_dict = {
            "template@odata.bind": "https://graph.microsoft.com/v1.0/teamsTemplates('standard')",
            "group@odata.bind": f"https://graph.microsoft.com/v1.0/groups('{grp_id}')"
        }

        data_json = json.dumps(data_dict)

        try:
            delay = 15
            delay_max = 90
            logteams.info(f"Creating a new TEAMS site for '{groupname}'")
            # set owner first
            logteams.info(f"Verifying owner '{owner}' for '{groupname}'")
            if not self.verify_owner(groupname=groupname, owner=owner):
                logteams.info(f"Updating group owner to '{owner}'")
                owner_r = self.set_group_owner(groupname, owner_id=owner)
                if not owner_r:
                    logteams.error("Setting owner failed. Exiting.")
                    return False
                t = 0
                while not self.verify_owner(groupname=groupname, owner=owner):
                    logteams.info(f"Sleeping {delay} secs for propogation..")
                    sleep(delay)
                    t += delay
                    if t >= delay_max:
                        logteams.error(f"Propogation delay exceeded {delay_max} secs. Exiting")
                        return False

            site_chk = False
            t = 0
            while not site_chk:
                result = self.session.post(url=_endpoint, data=data_json, headers=raw_headers)
                if int(result.status_code) == 202:
                    site_chk = True
                    logteams.info(f"Successfully created a new TEAMS for '{groupname}'")
                    return True
                else:

                    logteams.info(f"Propogation delay. Sleep {delay} secs before retrying.")
                    sleep(delay)
                    t += delay
                    if t >= delay_max:
                        logteams.error(f"Propogation took longer than {delay_max} secs. Exiting.")
                        logteams.error(f"Enabling TEAMS for '{groupname}' failed with status {result.status_code}")
                        logteams.error(result.json())

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

            if int(result.status_code) == 200:
                logteams.info(f"A TEAMS site exists for group '{groupname}'")
                return result, True
            elif int(result.status_code) == 404:
                logteams.warning(f"A TEAMS site was not found for group '{groupname}'")
                return result, False
            else:
                logteams.error(f"Error while getting TEAMS for group '{groupname}', status code: {result.status_code}")
                return result, False

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
        resp, pre_check = self.get_teams(groupname)
        if pre_check:
            site_found = True
        else:
            site_found = False

        # if site doesnt exist create one
        if not site_found:
            result = self.create_team_from_group(groupname, owner=owner)
            if not result:
                logteams.error(f"Failed to create TEAMS site for '{groupname}'")
                return False

        # verify owner for group
        logteams.info(f"Verifying owner for group '{groupname}'")
        g_owner = self.verify_owner(groupname=groupname, owner=owner)
        if not g_owner:
            logteams.info(f"Updating group owner to '{owner}'")
            result = self.set_group_owner(groupname=groupname, owner_id=owner)

    def verify_owner(self, groupname, owner):
        """
        Verify if the group owner matches the owner arg passed
        :param groupname:
        :param owner:
        :return:
        """
        # get the group owner
        grp_owner = self.get_group_owner(groupname)
        if not grp_owner:
            logteams.error(f"Verify owner: Error while getting group owner for '{groupname}'")
            return False
        # get the user from AAD, we use onprem only objects here
        owner_obj = self.get_aad_user(loginid=owner, onprem=True)

        if not owner_obj:
            logteams.error(f"Verify owner: Unable to get user object for '{owner}'")
            return False

        grp_owner_id_lst = []

        # collect IDs for owners for the group
        for o in grp_owner.json()['value']:
            grp_owner_id_lst.append(o['id'])

        if owner_obj[0]['id'] in grp_owner_id_lst:
            logteams.info(f"Verify success: Owner '{owner}' is set for group '{groupname}")
            return True
        else:
            logteams.error(f"Verify failed: Owner '{owner}' is not set for group '{groupname}'")
            return False

    def new_365_group(self, groupname):
        """
        Create a new M365 group with owner set.
        :param groupname:
        :return:
        """

        result = self.create_aad_group(groupname=groupname, role_enable=False, gtype=365)
        if int(result.status_code) == 201:
            g = None
            timeout = None
            t = 0
            while all([not g, not timeout]):
                logteams.info("Propogation delay. Sleep 15 secs")
                sleep(15)
                g_o = self.get_aad_group(groupname)
                g = g_o['value']
                if not g:
                    t += 15
                    if t >= 60: timeout = True
                    logteams.error("Propogation took longer than 60 secs. Exiting.")
                    return g_o, False
                else:
                    logteams.info(f"Group '{groupname}' created successfully.")
                    return g_o, True
        else:
            logteams.error(f"Group creation has failed with status: {result.status_code}")
            return False



