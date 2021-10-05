import json
import os
import sys
import platform

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from az.helpers import my_logger
from az.helpers.config import config
from az.helpers.azureauth import AzureAd
from az.helpers import com_utils

if platform.system().lower() == 'windows':
    LOG_DIR = os.path.join('c:\\', 'logs', 'azgraph')
else:
    LOG_DIR = os.path.join(os.environ['VIRTUAL_ENV'], 'logs', 'azgraph')

logcap = my_logger.My_logger(logdir=LOG_DIR, logfile='azureca')


class AadCa(AzureAd):
    """
    Module to manage conditional access policies
    """

    def __init__(self, cert_auth=True, auto_rotate=False, days=30):
        super(AadCa, self).__init__(cert_auth=cert_auth, auto_rotate=auto_rotate, days=days)

    def list_all_cap(self):
        """
        List all defined conditional policies
        :return: dict or bool
        """
        raw_headers = {"Authorization": "Bearer " + self.auth['access_token'], "Content-type": "application/json"}
        _endpoint = config["apibetaurl"] + "/identity/conditionalAccess/policies"
        try:
            result = self.session.get(url=_endpoint, headers=raw_headers)
            cas_dict = result.json()
            return cas_dict

        except Exception as e:
            logcap.error(f'Exception: {e}, while making API call.')
            return False

    def export_all_cap(self, outdir):
        """
        Backup all current conditional policies to json files
        this wil create one file named all_ca_config.json with a snapshot of current polcies.
        a separate file will be created for each policy named with the object ID, this is the
        importable file in case a policy needs restored.
        :param outdir: target dir for output files
        :return:
        """

        cas_dict = self.list_all_cap()

        try:
            ca_export_dict = {}
            for ca in cas_dict['value']:
                ca_export_dict[ca['id']] = {}
                ca_export_dict[ca['id']]['displayName'] = ca['displayName']
                ca_export_dict[ca['id']]['state'] = ca['state']
                ca_export_dict[ca['id']]['grantControls'] = ca['grantControls']
                ca_export_dict[ca['id']]['conditions'] = ca['conditions']
                ca_export_dict[ca['id']]['sessionControls'] = ca['sessionControls']

            if os.path.isdir(outdir):
                for ca_conf in ca_export_dict.keys():
                    exp_fname = f'{ca_conf}.json'
                    exp_json = json.dumps(ca_export_dict[ca_conf], indent=4)
                    logcap.info(f'Writing config export for CA policy id {ca_conf}')
                    com_utils.write_out_file(outdir=outdir, filename=exp_fname, outlines=exp_json)

                cas_j_pretty = json.dumps(cas_dict, indent=4)
                full_dump_fname = "all_ca_config.json"
                logcap.info(f'Writing CA policies to file {full_dump_fname}')

                com_utils.write_out_file(outdir=outdir, filename=full_dump_fname, outlines=cas_j_pretty)

            else:
                logcap.error(f'Invalid outdir, path not found {outdir}')

        except Exception as e:
            logcap.error(f'Exception: {e} while writing out files')

    def import_cap(self, filename):
        """
        Import the given conditional policy JSON file to AAD
        :param filename: input file in json format
        :return:
        """
        raw_headers = {"Authorization": "Bearer " + self.auth['access_token'], "Content-type": "application/json"}
        _endpoint = config["apibetaurl"] + "/identity/conditionalAccess/policies"

        if os.path.isfile(filename):
            logcap.info(f'Reading CA policy config file {filename}')
            with open(filename) as f:
                ca_conf_dict = json.load(f)
                data_json = json.dumps(ca_conf_dict)
        else:
            logcap.error(f'Invalid filename/path not found for {filename}')
            return False

        try:
            cap_dict_lst = self.list_all_cap()
            cap_names_dict = {}
            for cap in cap_dict_lst['value']:
                cap_names_dict[cap['id']] = cap['displayName']

            conf_cap_name = ca_conf_dict['displayName']

            if len(cap_names_dict.values()) != len(set(cap_names_dict.values())):
                logcap.error('Multiple CA policies found with conflicting names. Exiting')
                return False

            if set(cap_names_dict.values()) & {conf_cap_name}:
                logcap.info(f'Found existing CA policy "{conf_cap_name}". Will update.')
                update = True
                create = False
                for k in cap_names_dict.keys():
                    if cap_names_dict[k] == conf_cap_name:
                        cap_id = k
                        continue
            else:
                logcap.info("Will import config as new CA policy object")
                create = True
                update = False
                cap_id = None

        except Exception as e:
            logcap.error(f'Exception while parsing config dict to import - {e}')
            return False

        try:
            logcap.info(f'Importing CA policy config from {filename} to Azure AD')
            if create:
                result = self.session.post(url=_endpoint, data=data_json, headers=raw_headers)
                if int(result.status_code) == 201:
                    logcap.info('Successfully imported CA access policy from file')
                    logcap.info(result.json())
                else:
                    logcap.error(f'Importing CA policy config file failed. Status code: {result.status_code}')
                    logcap.error(f'{result.text}')
                    return False
            elif update:
                result = self.session.patch(url=f'{_endpoint}/{cap_id}', data=data_json, headers=raw_headers)
                if int(result.status_code) == 204:
                    logcap.info('Successfully imported CA policy from file')
                    logcap.info(f'Status code: {result.status_code}')
                else:
                    logcap.error(f'Importing CA policy config file failed. Status code: {result.status_code}')
                    logcap.error(f'{result.text}')
                    return False

        except Exception as e:
            logcap.error(f'Exception: {e}, while making API call.')
            return False
