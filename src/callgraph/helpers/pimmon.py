import json
import platform
import os
from callgraph.helpers.aadiam import Aadiam
from callgraph.helpers import my_logger
from callgraph.helpers import com_utils
from callgraph.helpers.config import tenancy

if platform.system().lower() == 'windows':
    LOG_DIR = os.path.join('c:\\', 'logs', 'azgraph')
else:
    LOG_DIR = os.path.join(os.environ['VIRTUAL_ENV'], 'logs', 'azgraph')

logpim = my_logger.My_logger(logdir=LOG_DIR, logfile='pimmon')


class Pimmon(Aadiam):
    def __init__(self, cert_auth=True, auto_rotate=False, days=30):
        super(Aadiam, self).__init__(cert_auth=cert_auth, auto_rotate=auto_rotate, days=days)
        self.make_aad_roles_map()

    def make_pim_assignments_dict(self):
        """
        Create dict object with all eligible/active assignments for all AD roles and write a JSON file
        Application: RoleManagement.Read.Directory, RoleManagement.Read.All, RoleManagement.ReadWrite.Directory
        :return:
        """
        self.eligible_dict = {}
        self.eligible_dict_h = {}
        self.active_dict = {}
        self.active_dict_h = {}

        all_eligible = self.get_pim_eligibility_assignments()
        all_active = self.get_pim_assignment_schedule()

        if not hasattr(self, 'aad_roles_map_rev'):
            self.make_aad_roles_map()
        if not hasattr(self, 'aad_user_map'):
            self.make_aad_user_group_map()

        for id in all_eligible:
            if not id['roleDefinitionId'] in self.eligible_dict.keys():
                self.eligible_dict[id['roleDefinitionId']] = []
                self.eligible_dict_h[self.aad_roles_map_rev[id['roleDefinitionId']]] = []
                self.eligible_dict[id['roleDefinitionId']].append(id['principalId'])
                try:
                    self.eligible_dict_h[self.aad_roles_map_rev[id['roleDefinitionId']]].append(
                        self.aad_user_map[id['principalId']])
                except KeyError:
                    self.eligible_dict_h[self.aad_roles_map_rev[id['roleDefinitionId']]].append(id['principalId'])

            else:
                self.eligible_dict[id['roleDefinitionId']].append(id['principalId'])
                try:
                    self.eligible_dict_h[self.aad_roles_map_rev[id['roleDefinitionId']]].append(
                        self.aad_user_map[id['principalId']])
                except KeyError:
                    self.eligible_dict_h[self.aad_roles_map_rev[id['roleDefinitionId']]].append(id['principalId'])

        for id in all_active:
            if id['assignmentType'] == 'Assigned':
                if not id['roleDefinitionId'] in self.active_dict.keys():
                    self.active_dict[id['roleDefinitionId']] = []
                    self.active_dict_h[self.aad_roles_map_rev[id['roleDefinitionId']]] = []
                    self.active_dict[id['roleDefinitionId']].append(id['principalId'])
                    try:
                        self.active_dict_h[self.aad_roles_map_rev[id['roleDefinitionId']]].append(
                            self.aad_user_map[id['principalId']])
                    except KeyError:
                        self.active_dict_h[self.aad_roles_map_rev[id['roleDefinitionId']]].append(id['principalId'])
                else:
                    self.active_dict[id['roleDefinitionId']].append(id['principalId'])
                    try:
                        self.active_dict_h[self.aad_roles_map_rev[id['roleDefinitionId']]].append(
                            self.aad_user_map[id['principalId']])
                    except KeyError:
                        self.active_dict_h[self.aad_roles_map_rev[id['roleDefinitionId']]].append(id['principalId'])

    def write_all_assignment_json(self, outdir):
        """
        Create a JSON output of eligible assignments
        :return:
        """
        if not os.path.isdir(outdir):
            logpim.error(f"Path not found - '{outdir}'")
            return False

        logpim.info('Generating current eligible role assignments from Azure AD')
        self.make_pim_assignments_dict()
        out_fname = f"{tenancy.split('.')[0]}_eligible.json"
        outlines = json.dumps(self.eligible_dict, indent=4)
        logpim.info(f'Writing eligible assignments to file {os.path.join(outdir, out_fname)}')
        com_utils.write_out_file(outdir=outdir, filename=out_fname, outlines=outlines)

        logpim.info('Generating current eligible role assignments from Azure AD - human readable')
        self.make_pim_assignments_dict()
        out_fname = f"{tenancy.split('.')[0]}_eligible_hr.json"
        outlines = json.dumps(self.eligible_dict_h, indent=4)
        logpim.info(f'Writing eligible assignments to file {os.path.join(outdir, out_fname)}')
        com_utils.write_out_file(outdir=outdir, filename=out_fname, outlines=outlines)

        logpim.info('Generating current assigned role assignments from Azure AD')
        out_fname = f"{tenancy.split('.')[0]}_active.json"
        outlines = json.dumps(self.active_dict, indent=4)
        logpim.info(f'Writing active assignments to file {os.path.join(outdir, out_fname)}')
        com_utils.write_out_file(outdir=outdir, filename=out_fname, outlines=outlines)

        logpim.info('Generating current assigned role assignments from Azure AD - human readable')
        out_fname = f"{tenancy.split('.')[0]}_active_hr.json"
        outlines = json.dumps(self.active_dict_h, indent=4)
        logpim.info(f'Writing active assignments to file {os.path.join(outdir, out_fname)}')
        com_utils.write_out_file(outdir=outdir, filename=out_fname, outlines=outlines)

    def compare_eligible(self, inputdir=None, inputfile=None, giturl=None, gitrepo=None, gittoken=None,
                         branch="master"):
        """
        Compare the Azure AD eligible role assignments against "inputfile". Report any mismatches as errors
        :param inputfile: Input JSON file of eligible assignments
        :return:
        """
        logpim.title("Starting PIM Eligible assignments verification")
        if inputdir:
            if not os.path.isdir(inputdir):
                logpim.error(f"Path not found = '{inputdir}'")
                return False
            else:
                if not inputfile:
                    inputfile = os.path.join(inputdir, f"{tenancy.split('.')[0]}_eligible.json")
                if os.path.isfile(inputfile):
                    logpim.info(f'Loading reference assignments from "{inputfile}"')
                    with open(inputfile) as f:
                        ref_eligible_dict = json.load(f)
                else:
                    logpim.error(f'File not found - "{inputfile}"')
                    return False

        elif all([gitrepo, gittoken]):
            if not inputfile:
                inputfile = f"{tenancy.split('.')[0]}_eligible.json"

            gitfile = com_utils.github_get_file(base_url=giturl,
                                                repo=gitrepo,
                                                path=inputfile,
                                                git_token=gittoken,
                                                branch=branch)

            if gitfile:
                logpim.info(f'Loading reference assignments from git {giturl}/{gitrepo}/{inputfile}')
                ref_eligible_dict = json.loads(gitfile.read())
            else:
                logpim.error(f'Unable to fetch file form git repo.')
                return False
        else:
            logpim.error('Invalid args. Exiting.')
            return

        logpim.info('Generating Azure AD roles eligible assignments dict.')
        self.make_pim_assignments_dict()
        if not hasattr(self, 'aad_roles_map'):
            self.make_aad_roles_map()
        if not hasattr(self, 'aad_user_map'):
            self.make_aad_user_group_map()

        logpim.info('Comparing active roles in eligible assignments')
        if set(ref_eligible_dict.keys()) != set(self.eligible_dict.keys()):
            logpim.error('Eligible assignments roles differ')
            roles_not_in_ref = list(set(self.eligible_dict.keys()) - set(ref_eligible_dict.keys()))
            roles_not_in_ref_names = [self.aad_roles_map_rev[x] for x in roles_not_in_ref]
            roles_not_in_aad = list(set(ref_eligible_dict.keys()) - set(self.eligible_dict.keys()))
            roles_not_in_aad_names = [self.aad_roles_map_rev[x] for x in roles_not_in_aad]
            if roles_not_in_ref:
                logpim.error(f"PIM roles delta (role added): These roles defined in Azure AD, "
                             f"but not in reference file: {roles_not_in_ref_names}")
            if roles_not_in_aad:
                logpim.error(f"PIM roles delta (role removed): These roles are defined in reference file, but "
                             f"missing in Azure AD: {roles_not_in_aad_names}")

                for role in roles_not_in_aad:
                    missing_mems = [self.aad_user_map[m] for m in ref_eligible_dict[role]]
                    logpim.error(f"PIM Role missing eligible assignments: {self.aad_roles_map_rev[role]}:{missing_mems}")
        else:
            logpim.info('Eligible assignments roles match')

        logpim.info('Comparing individual roles for eligible assignments delta.')

        for ea in self.eligible_dict.keys():
            role_name = self.aad_roles_map_rev[ea]
            try:

                if self.eligible_dict[ea] == ref_eligible_dict[ea]:
                    logpim.info(f'Role verified successfully:"{role_name}"')
                else:
                    logpim.error(f'Role verification failed: "{role_name}"')

                    ea_not_in_ref = list(set(self.eligible_dict[ea]) - set(ref_eligible_dict[ea]))
                    # ea_not_in_ref_names = [self.aad_user_map[x] for x in ea_not_in_ref]

                    ea_not_in_ref_names = []
                    for x in ea_not_in_ref:
                        try:
                            ea_not_in_ref_names.append(self.aad_user_map[x])
                        except KeyError:
                            ea_not_in_ref_names.append(x)

                    ea_not_in_aad = list(set(ref_eligible_dict[ea]) - set(self.eligible_dict[ea]))
                    # ea_not_in_aad_names = [self.aad_user_map[x] for x in ea_not_in_aad]
                    ea_not_in_aad_names = []

                    for x in ea_not_in_aad:
                        try:
                            ea_not_in_aad_names.append(self.aad_user_map[x])
                        except KeyError:
                            ea_not_in_aad_names.append(x)

                    if ea_not_in_ref:
                        logpim.error(
                            f'PIM delta (assignment added): The following objects are in role "{role_name}" eligible assignment, '
                            f'but not found in reference file: {ea_not_in_ref_names}')
                    if ea_not_in_aad:
                        logpim.error(
                            f'PIM delta (assignment removed): The following objects are missing in role "{role_name}" eligible assignment, '
                            f'but found in reference file: {ea_not_in_aad_names}')
            except KeyError:
                logpim.error(f"Role definition '{role_name}' not found in reference file")

    def compare_active(self, inputdir=None, inputfile=None, giturl=None, gitrepo=None, gittoken=None,
                         branch="master"):
        """
        Compare current active PIM assignments against the inputfile
        :param inputfile:
        :return:
        """
        logpim.title("Starting PIM Active assignments verification")
        if inputdir:
            if not os.path.isdir(inputdir):
                logpim.error(f"Path not found = '{inputdir}'")
                return False
            else:
                if not inputfile:
                    inputfile = os.path.join(inputdir, f"{tenancy.split('.')[0]}_active.json")
                if os.path.isfile(inputfile):
                    logpim.info(f'Loading reference assignments from "{inputfile}"')
                    with open(inputfile) as f:
                        ref_active_dict = json.load(f)
                else:
                    logpim.error(f'File not found - "{inputfile}"')
                    return False

        elif all([gitrepo, gittoken]):
            if not inputfile:
                inputfile = f"{tenancy.split('.')[0]}_active.json"

            gitfile = com_utils.github_get_file(base_url=giturl,
                                                repo=gitrepo,
                                                path=inputfile,
                                                git_token=gittoken,
                                                branch=branch)

            if gitfile:
                logpim.info(f'Loading reference assignments from git {giturl}/{gitrepo}/{inputfile}')
                ref_active_dict = json.loads(gitfile.read())
            else:
                logpim.error(f'Unable to fetch file form git repo.')
                return False
        else:
            logpim.error('Invalid args. Exiting')
            return

        logpim.info('Generating Azure AD roles active assignments dict.')

        self.make_pim_assignments_dict()
        if not hasattr(self, 'aad_roles_map_rev'):
            self.make_aad_roles_map()
        if not hasattr(self, 'aad_user_map'):
            self.make_aad_user_group_map()

        logpim.info('Comparing active roles assignments')
        if set(ref_active_dict.keys()) != set(self.active_dict.keys()):
            logpim.error('Active assignment roles differ')
            roles_not_in_ref = list(set(self.active_dict.keys()) - set(ref_active_dict.keys()))
            roles_not_in_ref_names = [self.aad_roles_map_rev[x] for x in roles_not_in_ref]
            roles_not_in_aad = list(set(ref_active_dict.keys()) - set(self.active_dict.keys()))
            roles_not_in_aad_names = [self.aad_roles_map_rev[x] for x in roles_not_in_aad]
            if roles_not_in_ref:
                logpim.error(f"PIM roles delta (role added): These roles defined in Azure AD, "
                             f"but not in reference file: {roles_not_in_ref_names}")
            if roles_not_in_aad:
                logpim.error(f"PIM roles delta (role removed): These roles are defined in reference file, but"
                             f" missing in Azure AD: {roles_not_in_aad_names}")
                for role in roles_not_in_aad:
                    missing_mems = [self.aad_user_map[m] for m in ref_active_dict[role]]
                    logpim.error(f"PIM Role missing active assignments: {self.aad_roles_map_rev[role]}:{missing_mems}")
        else:
            logpim.info('Active assignment roles match')

        logpim.info('Comparing individual roles for active assignments delta.')
        for ea in self.active_dict.keys():
            role_name = self.aad_roles_map_rev[ea]
            try:
                if self.active_dict[ea] == ref_active_dict[ea]:
                    logpim.info(f'Role verified successfully:"{role_name}"')
                else:
                    logpim.error(f'Role verification failed: "{role_name}"')
                    ea_not_in_ref = list(set(self.active_dict[ea]) - set(ref_active_dict[ea]))
                    # ea_not_in_ref_names = [self.aad_user_map[x] for x in ea_not_in_ref]
                    ea_not_in_ref_names = []
                    for x in ea_not_in_ref:
                        try:
                            ea_not_in_ref_names.append(self.aad_user_map[x])
                        except KeyError:
                            ea_not_in_ref_names.append(x)

                    ea_not_in_aad = list(set(ref_active_dict[ea]) - set(self.active_dict[ea]))
                    # ea_not_in_aad_names = [self.aad_user_map[x] for x in ea_not_in_aad]
                    ea_not_in_aad_names = []
                    for x in ea_not_in_aad:
                        try:
                            ea_not_in_aad_names.append(self.aad_user_map[x])
                        except KeyError:
                            ea_not_in_aad_names.append(x)

                    if ea_not_in_ref:
                        logpim.error(
                            f'PIM delta (assignment added): The following objects are in role "{role_name}" active assignment, '
                            f'but not found in reference file: {ea_not_in_ref_names}')
                    if ea_not_in_aad:
                        logpim.error(
                            f'PIM delta (assignment removed): The following objects are missing in role "{role_name}" active assignment, '
                            f'but found in reference file: {ea_not_in_aad_names}')
            except KeyError:
                logpim.error(f"Role definition '{role_name}' not found in reference file")

    def make_aad_user_group_map(self):
        """
        Create a dict with id:dsiplayname for all azure ad users
        :return:
        """
        try:
            logpim.info('Creating Azure AD user ID map dict.')
            all_aad_users = self.get_aad_user()
            if all_aad_users:
                self.aad_user_map = {}
                for u in all_aad_users:
                    self.aad_user_map[u['id']] = u['displayName']
            else:
                logpim.error('Failed to get Azure AD user objects')
                return False
        except Exception as e:
            logpim.error(f'Unable to get Azure AD user objects - {e}')
            return False

        try:
            logpim.info('Creating Azure AD groups map dict.')
            self.make_aad_grp_id_map()
            self.aad_user_map.update(self.all_aad_grp_ids)
        except Exception as e:
            logpim.error(f"Exception while getting Azure AD groups - {e}")
            return False
