import json
import platform
import os
from callgraph.helpers import aadiam
from callgraph.helpers import my_logger
from callgraph.helpers import com_utils
from callgraph.helpers.config import tenancy

if platform.system().lower() == 'windows':
    LOG_DIR = os.path.join('c:\\', 'logs', 'azgraph')
else:
    LOG_DIR = os.path.join(os.environ['VIRTUAL_ENV'], 'logs', 'azgraph')

logpim = my_logger.My_logger(logdir=LOG_DIR, logfile='pimmon')


class Pimmon(object):
    def __init__(self):
        self.aad = aadiam.Aadiam()
        self.aad.make_aad_roles_map()


    def make_pim_assignments_dict(self):
        """
        Create dict object with all eligible/active assignments for all AD roles and write a JSON file
        :return:
        """
        self.eligible_dict = {}
        self.active_dict = {}

        all_eligible = self.aad.get_pim_eligibility_assignments()
        all_active = self.aad.get_pim_assignment_schedule()

        for id in all_eligible['value']:
            if not id['roleDefinitionId'] in self.eligible_dict.keys():
                self.eligible_dict[id['roleDefinitionId']] = []
                self.eligible_dict[id['roleDefinitionId']].append(id['principalId'])
            else:
                self.eligible_dict[id['roleDefinitionId']].append(id['principalId'])

        for id in all_active['value']:
            if id['assignmentType'] == 'Assigned':
                if not id['roleDefinitionId'] in self.active_dict.keys():
                    self.active_dict[id['roleDefinitionId']] = []
                    self.active_dict[id['roleDefinitionId']].append(id['principalId'])
                else:
                    self.active_dict[id['roleDefinitionId']].append(id['principalId'])


    def write_all_assignment_json(self, outdir):
        """
        Create a JSON output of eligible assignments
        :return:
        """
        logpim.info('Generating current eligible role assignments from Azure AD')
        self.make_pim_assignments_dict()
        out_fname = f"{tenancy.split('.')[0]}_eligible.json"
        outlines = json.dumps(self.eligible_dict, indent=4)
        logpim.info(f'Writing eligible assignments to file {os.path.join(outdir, out_fname)}')
        com_utils.write_out_file(outdir=outdir, filename=out_fname, outlines=outlines)

        logpim.info('Generating current assigned role assignments from Azure AD')
        out_fname = f"{tenancy.split('.')[0]}_active.json"
        outlines = json.dumps(self.active_dict, indent=4)
        logpim.info(f'Writing active assignments to file {os.path.join(outdir, out_fname)}')
        com_utils.write_out_file(outdir=outdir, filename=out_fname, outlines=outlines)


    def compare_eligible(self, inputfile):
        """
        Compare the Azure AD eligible role assignments against "inputfile". Report any mismatches as errors
        :param inputfile: Input JSON file of eligible assignments
        :return:
        """
        if os.path.isfile(inputfile):
            logpim.info(f'Loading reference assignemts from "{inputfile}"')
            with open(inputfile) as f:
                ref_eligible_dict = json.load(f)

        logpim.info('Generating Azure AD roles eligible assignments dict.')
        self.make_pim_assignments_dict()
        if not hasattr(self.aad, 'aad_roles_map'):
            self.aad.make_aad_roles_map()
        if not hasattr(self, 'aad_user_map'):
            self.make_aad_user_map()

        logpim.info('Comparing active roles in eligible assignments')
        if set(ref_eligible_dict.keys()) != set(self.eligible_dict.keys()):
            logpim.error('Eligible assignment roles differ')
            roles_not_in_ref = list(set(self.eligible_dict.keys()) - set(ref_eligible_dict.keys()))
            roles_not_in_ref_names = [self.aad.aad_roles_map_rev[x] for x in roles_not_in_ref]
            roles_not_in_aad = list(set(ref_eligible_dict.keys()) - set(self.eligible_dict.keys()))
            roles_not_in_aad_names = [self.aad.aad_roles_map_rev[x] for x in roles_not_in_aad]
            if roles_not_in_ref:
                logpim.error(f"PIM roles delta: These roles defined in Azure AD, "
                             f"but not in reference file: {roles_not_in_ref_names}")
            if roles_not_in_aad:
                logpim.error(f"PIM roles delta: These roles are defined in reference file, but"
                             f"missing in Azure AD: {roles_not_in_aad_names}")
        else:
            logpim.info('Roles match for eligible assignments')

        logpim.info('Comparing individual roles for eligible assignments delta.')
        for ea in self.eligible_dict.keys():
            role_name = self.aad.aad_roles_map_rev[ea]
            try:
                if self.eligible_dict[ea] == ref_eligible_dict[ea]:
                    logpim.info(f'Role verified successfully:"{role_name}"')
                else:
                    logpim.error(f'Role failed verification: "{role_name}"')
                    ea_not_in_ref = list(set(self.eligible_dict[ea]) - set(ref_eligible_dict[ea]))
                    ea_not_in_ref_names = [self.aad_user_map[x] for x in ea_not_in_ref]

                    ea_not_in_aad = list(set(ref_eligible_dict[ea]) - set(self.eligible_dict[ea]))
                    ea_not_in_aad_names = [self.aad_user_map[x] for x in ea_not_in_aad]

                    if ea_not_in_ref:
                        logpim.error(f'PIM delta: The following objects are in role "{role_name}" eligible assignments, '
                                      f'but not in reference file: {ea_not_in_ref_names}' )
                    if ea_not_in_aad:
                        logpim.error(f'PIM delta: The following objects are not in role "{role_name}" eligible assignments,'
                                     f'but found in reference file: {ea_not_in_aad_names}')
            except KeyError:
                logpim.error(f"Role definition '{role_name}' not found in reference file")


    def compare_active(self, inputfile):
        """
        Compare current active PIM assignments against the inputfile
        :param inputfile:
        :return:
        """
        if os.path.isfile(inputfile):
            logpim.info(f'Loading reference assignments from "{inputfile}"')
            with open(inputfile) as f:
                ref_active_dict = json.load(f)

        logpim.info('Generating Azure AD roles active assignments dict.')

        self.make_pim_assignments_dict()
        if not hasattr(self.aad, 'aad_roles_map_rev'):
            self.aad.make_aad_roles_map()
        if not hasattr(self, 'aad_user_map'):
            self.make_aad_user_map()

        logpim.info('Comparing active roles in assignments')
        if set(ref_active_dict.keys()) != set(self.active_dict.keys()):
            logpim.error('Active assignment roles differ')
            roles_not_in_ref = list(set(self.active_dict.keys()) - set(ref_active_dict.keys()))
            roles_not_in_ref_names = [self.aad.aad_roles_map_rev[x] for x in roles_not_in_ref]
            roles_not_in_aad = list(set(ref_active_dict.keys()) - set(self.active_dict.keys()))
            roles_not_in_aad_names = [self.aad.aad_roles_map_rev[x] for x in roles_not_in_aad]
            if roles_not_in_ref:
                logpim.error(f"PIM roles delta: These roles defined in Azure AD, "
                             f"but not in reference file: {roles_not_in_ref_names}")
            if roles_not_in_aad:
                logpim.error(f"PIM roles delta: These roles are defined in reference file, but"
                             f"missing in Azure AD: {roles_not_in_aad_names}")
        else:
            logpim.info('Roles match for active assignments')

        logpim.info('Comparing individual roles for active assignments delta.')
        for ea in self.active_dict.keys():
            role_name = self.aad.aad_roles_map_rev[ea]
            try:
                if self.active_dict[ea] == ref_active_dict[ea]:
                    logpim.info(f'Role verified successfully:"{role_name}"')
                else:
                    logpim.error(f'Role failed verification: "{role_name}"')
                    ea_not_in_ref = list(set(self.active_dict[ea]) - set(ref_active_dict[ea]))
                    ea_not_in_ref_names = [self.aad_user_map[x] for x in ea_not_in_ref]

                    ea_not_in_aad = list(set(ref_active_dict[ea]) - set(self.active_dict[ea]))
                    ea_not_in_aad_names = [self.aad_user_map[x] for x in ea_not_in_aad]

                    if ea_not_in_ref:
                        logpim.error(f'PIM delta: The following objects are in role "{role_name}" active assignments, '
                                     f'but not in reference file: {ea_not_in_ref_names}')
                    if ea_not_in_aad:
                        logpim.error(f'PIM delta: The following objects are not in role "{role_name}" active assignments,'
                                     f'but found in reference file: {ea_not_in_aad_names}')
            except KeyError:
                logpim.error(f"Role definition '{role_name}' not found in reference file")


    def make_aad_user_map(self):
        """
        Create a dict with id:dsiplayname for all azure ad users
        :return:
        """
        try:
            logpim.info('Creating Azure AD user ID map dict.')
            all_aad_users = self.aad.get_aad_user()
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




