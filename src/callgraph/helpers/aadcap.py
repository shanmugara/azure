import ipaddress
import json
import os
import sys
import platform
import re

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from callgraph.helpers import my_logger
from callgraph.helpers.config import config, tenancy
from callgraph.helpers.azureauth import AzureAd
from callgraph.helpers import com_utils

if platform.system().lower() == 'windows':
    LOG_DIR = os.path.join('c:\\', 'logs', 'azgraph')
else:
    LOG_DIR = os.path.join(os.environ['VIRTUAL_ENV'], 'logs', 'azgraph')

logcap = my_logger.My_logger(logdir=LOG_DIR, logfile='azureca')


class AadCa(AzureAd):
    """
    Module to manage conditional access policies and named locations
    App permissions: Application.Read.All, Policy.Read.All, Policy.ReadWrite.ConditionalAccess
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
                tenancy_short = tenancy.split('.')[0]
                for ca_conf in ca_export_dict.keys():
                    displayname_str = re.sub("[^0-9a-zA-Z]+", "_", ca_export_dict[ca_conf]['displayName'])
                    exp_fname = f"{tenancy_short}_{displayname_str}.json"
                    exp_json = json.dumps(ca_export_dict[ca_conf], indent=4)
                    logcap.info(f'Writing config export for CA policy id {ca_conf}')
                    com_utils.write_out_file(outdir=outdir, filename=exp_fname, outlines=exp_json)

                cas_j_pretty = json.dumps(cas_dict, indent=4)
                full_dump_fname = f"{tenancy_short}_all_ca_config.json"
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

    def get_nl(self, name=None):
        """
        Get named locations for conditional access policies
        :param name:
        :return:
        """
        raw_headers = {"Authorization": "Bearer " + self.auth['access_token'], "Content-type": "application/json"}
        _endpoint = config["apiurl"] + "/identity/conditionalAccess/namedLocations"

        if name:
            _filter = f"?$filter=displayName eq '{name}'"
            _endpoint += _filter

        try:
            result = self.session.get(url=_endpoint, headers=raw_headers)
            if int(result.status_code) == 200:
                r_json = result.json()
                if not r_json['value']:
                    logcap.warning('No matching named locations were found')
                return r_json
            else:
                logcap.error(f'APi call to get named locations failed with status code - {result.status_code}')
                return False
        except Exception as e:
            logcap.error(f'API call to get named locations failed with exception - {e}')
            return False

    def export_nl(self, outdir, name=None):
        """
        List all named locations defined and export as CSV
        :param name: name of the named location, default is None to return all named locations
        :param outdir: output path to write the exported csv
        :return:
        """
        try:
            nl_dict = self.get_nl(name=name)
            if all([nl_dict, nl_dict['value']]):
                for nl in nl_dict['value']:
                    cidr_lst = []
                    cidr_lst.append(f"#nltenancy:{tenancy}\n")
                    cidr_lst.append(f"#id:{nl['id']}\n")
                    cidr_lst.append(f"#displayName:{nl['displayName']}\n")
                    cidr_lst.append(f"#isTrusted:{nl['isTrusted']}\n")

                    for cidr in nl['ipRanges']:
                        cidr_lst.append(cidr['cidrAddress'] + '\n')
                    # write export csv
                    fn = f"{tenancy.split('.')[0]}_nl_{nl['displayName']}.csv".lower()
                    com_utils.write_out_file(outdir=outdir, filename=fn, outlines=cidr_lst)

        except Exception as e:
            logcap.error(f'Getting named locations failed with exception - {e}')
            return False

    def update_nl(self, filepath=None):
        """
        Update an existing named location
        :param filepath: path to the CSV file to import
        CSV must include at least one of these identifier lines
        #displayName:Name of the named location
        #id:object id of the named location
        If Trusted is not defined, default is untrusted
        #isTrust:True|False
        :return:
        """
        if filepath:
            if not os.path.isfile(filepath):
                logcap.error(f'File path not found - {filepath}')
                return False

            id, displayName, isTrusted, _invalid_ips, cidr_ips_lst, nl_tenancy = self.parse_nl_csv(filepath)

            if _invalid_ips:
                logcap.error('Found invalid cidr notations, wont proceed. Exiting')
                return False

            if nl_tenancy != tenancy:
                logcap.error(f'Tenancy name mismatch between csv and config.py. wont proceed.')
                return False

            if id:
                logcap.info(f'Found object id {id} in CSV, will use this to update object')

            elif displayName:
                logcap.info(f'Found object displayName {displayName} in CSV, will obtain object id')
                nl_obj = self.get_nl(name=displayName)
                if nl_obj['value']:
                    id = nl_obj['value'][0]['id']
                else:
                    logcap.error('Unable to find a matching named location')
                    return False
            else:
                logcap.error('Unable to find either displayName or id attributes in the CSV. Exiting')
                return False

            iprange_lst = []
            for cr in cidr_ips_lst:
                iprange_lst.append(
                    {
                        "@odata.type": "#microsoft.graph.iPv4CidrRange",
                        "cidrAddress": cr
                    }
                )

            data_dict = {
                "@odata.type": "#microsoft.graph.ipNamedLocation",
                "displayName": displayName,
                "isTrusted": isTrusted,
                "ipRanges": iprange_lst,
            }

            data_json = json.dumps(data_dict)

            raw_headers = {"Authorization": "Bearer " + self.auth['access_token'], "Content-type": "application/json"}
            _endpoint = config["apiurl"] + f"/identity/conditionalAccess/namedLocations/{id.strip()}"

            logcap.info(f'Updating named location object {id}, {displayName}')

            try:
                result = self.session.patch(url=_endpoint, data=data_json, headers=raw_headers)
                if int(result.status_code) == 204:
                    logcap.info(f'Successfully updated named location {displayName}')
                    return result
                else:
                    logcap.error(f'Updating named location {displayName} failed with status code {result.status_code}')
                    return result
            except Exception as e:
                logcap.error(f'Updating named location {displayName} failed with exception {e}')
                return False

    def create_nl(self, filepath):
        """
        Create a new named location using the input file
        :param filepath:
        :return:
        """
        if filepath:
            if not os.path.isfile(filepath):
                logcap.error(f'File path not found - {filepath}')
                return False

            id, displayName, isTrusted, _invalid_ips, cidr_ips_lst, nl_tenancy = self.parse_nl_csv(filepath)

            if _invalid_ips:
                logcap.error('Found invalid cidr notations, wont proceed. Exiting')
                return False

            if nl_tenancy != tenancy:
                logcap.error(f'Tenancy name mismatch between csv and config.py. wont proceed.')
                return False

            if displayName:
                nl_obj = self.get_nl(name=displayName)
                if nl_obj['value']:
                    id = nl_obj['value'][0]['id']
                    logcap.error(f'Found an existing named location {displayName}, {id}. Wont create. Exiting')
                    return False
            else:
                logcap.error('Unable to find displayName attributed in the CSV. Exiting')
                return False

            iprange_lst = []
            for cr in cidr_ips_lst:
                iprange_lst.append(
                    {
                        "@odata.type": "#microsoft.graph.iPv4CidrRange",
                        "cidrAddress": cr
                    }
                )

            data_dict = {
                "@odata.type": "#microsoft.graph.ipNamedLocation",
                "displayName": displayName,
                "isTrusted": isTrusted,
                "ipRanges": iprange_lst,
            }

            data_json = json.dumps(data_dict)

            raw_headers = {"Authorization": "Bearer " + self.auth['access_token'], "Content-type": "application/json"}
            _endpoint = config["apiurl"] + f"/identity/conditionalAccess/namedLocations"

            logcap.info(f'Creating new named location object {displayName}')

            try:
                result = self.session.post(url=_endpoint, data=data_json, headers=raw_headers)
                if int(result.status_code) == 201:
                    logcap.info(f'Successfully created named location {displayName}')
                    return result
                else:
                    logcap.error(f'Creating named location {displayName} failed with status code {result.status_code}')
                    return result
            except Exception as e:
                logcap.error(f'Creating named location {displayName} failed with exception {e}')
                return False


    @staticmethod
    def parse_nl_csv(filepath):
        """
        Parse the given CSV and validate syntax,and return required attributes to caller
        :param filepath: file to parse
        :return: cidr_dict, id, displayName, invalid_ips
        """
        id = None
        displayName = None
        isTrusted = False
        _invalid_ips = False
        nl_tenancy = None

        with open(filepath) as f:
            lines = f.readlines()
            cidr_ips_lst = []
            _invalid_ips = False

            for line in lines:
                if line.startswith('#displayName'):
                    displayName = line.split(':')[1].strip()
                elif line.startswith('#id'):
                    id = line.split(':')[1].strip()
                elif line.startswith('#isTrusted'):
                    isTrusted = line.split(':')[1].strip()
                elif line.startswith('#nltenancy:'):
                    nl_tenancy = line.split(':')[1].strip()
                elif line.startswith('#'):
                    pass #commented line
                else:
                    try:
                        net_o = ipaddress.ip_network(line.strip())
                        cidr_ips_lst.append(line.strip())
                    except ValueError:
                        logcap.error(f'Line {line.strip()} is not a valid ip cidr. Please fix the error')
                        _invalid_ips = True

        return id, displayName, isTrusted, _invalid_ips, cidr_ips_lst, nl_tenancy

