import time
import json
import os
import sys
import platform
import re
import functools
import timeit
from datetime import datetime

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from az.helpers import my_logger
from az.helpers.config import config
from az.helpers import powershell
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


    def export_all_cap(self, outdir):
        """
        Backup all current conditional policies to json files
        this wil create one file named all_ca_config.json with a snapshot of current polcies.
        a separate file will be created for each policy named with the object ID, this is the
        importable file in case a policy needs restored.
        :param outdir: target dir for output files
        :return:
        """

        raw_headers = {"Authorization": "Bearer " + self.auth['access_token'], "Content-type": "application/json"}
        _endpoint = config["apiurl"] + "/identity/conditionalAccess/policies"
        try:
            result = self.session.get(url=_endpoint, headers=raw_headers)
            cas_dict = result.json()

        except Exception as e:
            logcap.error(f'Exception: {e}, while making API call.')
            return False

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
                    exp_fname = os.path.join(outdir, f'{ca_conf}.json')
                    exp_json = json.dumps(ca_export_dict[ca_conf], indent=4)
                    logcap.info(f'Writing config export for policy id {ca_conf}')
                    with open(exp_fname, 'w') as f:
                        f.write(exp_json)

                cas_j_pretty = json.dumps(cas_dict, indent=4)
                full_dump_fname = os.path.join(outdir, "all_ca_config.json")
                with open(full_dump_fname, 'w') as f:
                    logcap.info(f'Writing conditional policies to file {full_dump_fname}')
                    lines = cas_j_pretty.splitlines()
                    for line in lines:
                        f.write(f'{line}\n')
            else:
                logcap.error(f'Invalid outdir, path not found {outdir}')

            return result

        except Exception as e:
            logcap.error(f'Exception: {e} while writing out files')

    def import_cap(self, filename):
        """
        Import the given conditonal policy JSON file to AAD
        :param filename: input file in json format
        :return:
        """
        raw_headers = {"Authorization": "Bearer " + self.auth['access_token'], "Content-type": "application/json"}
        _endpoint = config["apiurl"] + "/identity/conditionalAccess/policies"

        if os.path.isfile(filename):
            logcap.info(f'Reading ca config file {filename}')
            with open(filename) as f:
                ca_conf_dict = json.load(f)
                data_json = json.dumps(ca_conf_dict)
        try:
            logcap.info(f'Importing ca config from {filename} to Azure AD')
            result = self.session.post(url=_endpoint, data=data_json, headers=raw_headers)
            if int(result.status_code) == 201:
                logcap.info('Successfully imported conditional access policy from file')
                logcap.info(result.json())
            else:
                logcap.error(f'Importing config file failed. Status code: {result.status_code}')
                logcap.error(f'{result.text}')
                return False

        except Exception as e:
            logcap.error(f'Exception: {e}, while making API call.')
            return False



