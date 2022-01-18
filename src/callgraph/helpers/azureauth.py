import msal
import requests
import os
import sys
import urllib3
import platform
import base64
import functools
import timeit
import json
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from datetime import datetime

from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from callgraph.helpers import my_logger
from callgraph.helpers import pki_helper
from callgraph.helpers.config import config, cert, user, tenancy
from callgraph.helpers.version import version

if platform.system().lower() == 'windows':
    LOG_DIR = os.path.join('c:\\', 'logs', 'azgraph')
else:
    LOG_DIR = os.path.join(os.environ['VIRTUAL_ENV'], 'logs', 'azgraph')

log = my_logger.My_logger(logdir=LOG_DIR, logfile='azureauth')
liclog = my_logger.My_logger(logdir=LOG_DIR, logfile='licence')
pki = pki_helper.Cert()


class AzureAd(object):
    """
    Auth class
    """

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
        log.title(f"Callgraph v{version} - Authenticating to Azure AD")
        log.info('Current Azure tenancy: {}'.format(tenancy))

        if self.cert_auth:
            self.client_credentials = self.get_cert_creds()
            self.init_app_confidential()
        else:
            self.client_credentials = user["client_secret"]
            self.init_app()

        self.init_token()

        if auto_rotate:
            log.info('Automated cert rotation is enabled. Checking cert validity.')
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
            log.title("User Authentication")
            log.info(f"User account: {user['username']}")
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
                log.error("Visit this to consent:{}".format(self.app.get_authorization_request_url(scopes=user["scope"])))

    def get_cert_creds(self):
        """
        Get cert creds dict
        :return:
        """
        log.title("Certificate Authentication")
        if all([os.path.isfile(cert['cert_path']), os.path.isfile(cert['cert_key_path'])]):
            log.info(f"Cert file: {cert['cert_path']}")
            log.info(f"Key file: {cert['cert_key_path']}")
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

    def app_add_cert(self, certfile, keyfile, objectid=None):
        """
        Add a new cert to the application in AAD
        :param certfile: new cert file path
        :param keyfile: new keyfile path
        :param objectid: Object Id of the application registration
        :return:
        """

        if all([os.path.isfile(certfile), os.path.isfile(keyfile)]):
            data_dict = pki.rotate_cert(newcert=certfile, newkey=keyfile)
            if not data_dict:
                log.error('Unable to get new cert_dict')
                return False
        else:
            log.error('Unable to find either certfile or keyfile path. Exiting')
            return False

        if not objectid:
            if config.get('object_id'):
                # app_obj = self.get_app(objectid=config['client_id'])
                app_id = config['object_id']
            else:
                log.error('Unable to find object_id in config.py. Exiting app_add_cert')
                return False
        else:
            app_id = objectid

        raw_headers = {"Authorization": "Bearer " + self.auth['access_token'], "Content-type": "application/json"}
        _endpoint = config["apiurl"] + f'/applications/{app_id}/addKey'

        data_json = json.dumps(data_dict)

        try:
            result = self.session.post(url=_endpoint, data=data_json, headers=raw_headers)
            if int(result.status_code) == 200:
                log.info('Add cert result code: {}'.format(result.status_code))
            else:
                log.error('Add cert result code: {}'.format(result.status_code))
            return result

        except Exception as e:
            log.error('Exception {} while adding cert to app "{}"'.format(e, config['client_id']))
            return False

    def app_remove_cert(self, certid, objectid=None):
        """
        Remove a given cert from the app
        :param certid: id of the cert to remove
        :return:
        """
        if not objectid:
            if config.get('object_id'):
                # app_obj = self.get_app(objectid=config['client_id'])
                app_id = config['object_id']
            else:
                log.error('Unable to find object_id in config.py. Exiting app_add_cert')
                return False
        else:
            app_id = objectid

        raw_headers = {"Authorization": "Bearer " + self.auth['access_token'], "Content-type": "application/json"}
        _endpoint = config["apiurl"] + f'/applications/{app_id}/removeKey'

        jwt = pki.get_jwt(keyfile=cert['cert_key_path'])

        data_dict = {
            "keyId": certid,
            "proof": jwt
        }

        data_json = json.dumps(data_dict)

        try:
            result = self.session.post(url=_endpoint, data=data_json, headers=raw_headers)
            if int(result.status_code) == 204:
                log.info('Remove cert result code: {}'.format(result.status_code))
            else:
                log.error('Remove cert result code: {}'.format(result.status_code))
            return result

        except Exception as e:
            log.error('Exception {} while deleting cert id "{}"'.format(e, certid))
            return False

    def get_app(self, objectid):
        """
        Get the AAD application reg object
        :param objectid: Object OF of the application registration
        :return:
        """

        raw_headers = {"Authorization": "Bearer " + self.auth['access_token'], "Content-type": "application/json"}
        _endpoint = config["apiurl"] + f'/applications/{objectid}'

        try:
            result = self.session.get(url=_endpoint, headers=raw_headers)

            if int(result.status_code) == 200:
                app = result.json()
                return app
                # for app in apps['value']:
                #     if app['appId'] == objectid:
                #         return app

                # log.error('Unable to find app reg matching clientid {}'.format(objectid))
                # return False

            else:
                log.error('Get apps result: {}'.format(result.status_code))
                return False

        except Exception as e:
            log.error('Exception {} while getting app reg object id:"{}"'.format(e, config['app_id']))
            return False

    def rotate_this_cert(self, days=30, force=False):
        """
        Check the cert used by this app. If it is close to expire, rotate
        :param days: Number days remaining in the cert before it is rotated
        :return:
        """
        # Get cert thumb print
        this_cert_thumbprint = pki.cert_thumbprint(cert['cert_path']).upper()

        # Get the app object
        if config.get('object_id'):
            this_app = self.get_app(config['object_id'])
        else:
            log.error("Did not find an object_id for the application in config.py. Won't rotate cert.")
            return False

        # Get the expiry for this cert
        this_cert = {}
        for app_cert in this_app['keyCredentials']:
            if app_cert['customKeyIdentifier'] == this_cert_thumbprint:
                this_cert = app_cert
                break

        if not this_cert:
            log.error('Did not find a matching cert in app reg. Exiting')
            return

        exp_time = datetime.strptime(this_cert['endDateTime'], '%Y-%m-%dT%H:%M:%SZ')
        now_time = datetime.now()
        diff_time = exp_time - now_time

        if not force:
            if diff_time.days <= days:
                log.warning('Current cert validity remaining days: {}'.format(diff_time.days))
                log.warning('Current cert will be rotated')
            else:
                log.info('Current cert is still valid. Remaining days: {}'.format(diff_time.days))
                return
        else:
            log.info('Forced cert rotation requested. Will proceed to rotate cert.')

        # if close to expire, generate new cert
        log.info('Generating new cert and key files')
        cert_dir = os.path.split(cert['cert_path'])[0]
        cer_prefix = datetime.strftime(now_time, '%Y%m%d-%H%M%S')
        pki.create_self_signed(cn=this_app['displayName'], destpath=cert_dir)

        new_cert_path = os.path.join(cert_dir, this_app['displayName'] + '_cert.pem')
        new_key_path = os.path.join(cert_dir, this_app['displayName'] + '_key.pem')

        if not all([os.path.isfile(new_cert_path), os.path.isfile(new_key_path)]):
            log.error('Did not find new cert/key generated in path {}'.format(cert_dir))
            return

        # Add new cert to app
        log.info('Adding the new cert to app client_id:{}'.format(config['client_id']))
        resp = self.app_add_cert(certfile=new_cert_path, keyfile=new_key_path, objectid=this_app['id'])
        if not resp:
            log.error('Failed to add the new cert to app client_id:{}. exiting..'.format(config['client_id']))
            return

        # Rename cert files
        log.info('Renaming cert files..')
        bak_cert_fname = cert['cert_path'] + '.' + cer_prefix
        bak_key_fname = cert['cert_key_path'] + '.' + cer_prefix
        log.info('Renaming old cert file {} to {}'.format(cert['cert_path'], bak_cert_fname))
        os.rename(cert['cert_path'], bak_cert_fname)

        log.info('Renaming old key file {} to {}'.format(cert['cert_key_path'], bak_key_fname))
        os.rename(cert['cert_key_path'], bak_key_fname)

        log.info('Renaming new cert file {} to {}'.format(new_cert_path, cert['cert_path']))
        os.rename(new_cert_path, cert['cert_path'])

        log.info('Renaming new key file {} to {}'.format(new_key_path, cert['cert_key_path']))
        os.rename(new_key_path, cert['cert_key_path'])

        # remove old cert from app
        log.info('Removing old cert keyid {} from app client_id:{}'.format(this_cert['keyId'], config['client_id']))
        resp = self.app_remove_cert(certid=this_cert['keyId'], objectid=this_app['id'])
        if not resp:
            log.error('Removing cert failed..')
        elif int(resp.status_code) == 204:
            log.info('Successfully deleted old cert keyid:{} from app client_id:{}'.format(this_cert['keyId'],
                                                                                              config['client_id']))
        else:
            log.error('Removing old cert failed with status code {}'.format(resp.status_code))