"""
A module to extract cert and key from a PFX file.
"""
from pathlib import Path
import os
import platform
import sys
import base64
import json

from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    NoEncryption,
)
from cryptography.hazmat.primitives.serialization.pkcs12 import (
    load_key_and_certificates,
)
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
import jwt
import datetime

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from az.helpers import my_logger

try:
    from az.helpers.config import config, cert
except Exception as e:
    pass

if platform.system().lower() == 'windows':
    LOG_DIR = os.path.join('c:\\', 'logs', 'azgraph')
else:
    LOG_DIR = os.path.join(os.environ['VIRTUAL_ENV'], 'logs', 'azgraph')

logpki = my_logger.My_logger(logdir=LOG_DIR, logfile='certmod')


class Cert(object):
    """
    Cert management class
    """
    def pfx_to_pem(self, pfx_path, pfx_password):
        """
        Decrypts the .pfx file to cert and key file
        :param pfx_path: pfx file path to extract
        :param pfx_password: password for pfx file
        """

        pfx = Path(pfx_path).read_bytes()
        private_key, main_cert, add_certs = load_key_and_certificates(
            pfx, pfx_password.encode("utf-8"), None
        )

        out_dir = os.path.split(Path(pfx_path))[0]
        cert_file_out = os.path.join(out_dir, "mycertfile.pem")
        cert_key_out = os.path.join(out_dir, "mycertkey.pem")

        try:
            with open(cert_key_out, "wb") as pem_file:
                logpki.info("*** Writing key file to {}".format(cert_key_out))
                pem_file.write(
                    private_key.private_bytes(
                        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
                    )
                )

            with open(cert_file_out, "wb") as pem_file:
                logpki.info("*** Writing cert file to {}".format(cert_file_out))
                pem_file.write(main_cert.public_bytes(Encoding.PEM))
                for ca in add_certs:
                    pem_file.write(ca.public_bytes(Encoding.PEM))
        except Exception as e:
            logpki.error("Exception {} while writing out file".format(e))


    def create_self_signed(self, cn, destpath):
        """
        Generate a self signed cert/key and store in destpath
        :param cn: CN for cert
        :param destpath: destination path
        :return:
        """
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        if os.path.isdir(destpath):
            try:
                key_file = os.path.join(destpath, "{}_key.pem".format(cn))
                with open(key_file, "wb") as f:
                    logpki.info('Writing key file to {}'.format(key_file))
                    f.write(
                        key.private_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PrivateFormat.PKCS8,
                            encryption_algorithm=serialization.NoEncryption(),
                        )
                    )
                cert_file = os.path.join(destpath, "{}_cert.pem".format(cn))
                subject = issuer = x509.Name(
                    [
                        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
                        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"NY"),
                        x509.NameAttribute(NameOID.LOCALITY_NAME, u"New York"),
                        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Bloomberg L.P."),
                        x509.NameAttribute(NameOID.COMMON_NAME, u"{}".format(cn)),
                    ]
                )
                cert = (
                    x509.CertificateBuilder()
                        .subject_name(subject)
                        .issuer_name(issuer)
                        .public_key(key.public_key())
                        .serial_number(x509.random_serial_number())
                        .not_valid_before(datetime.datetime.utcnow())
                        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
                        .add_extension(
                        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
                        critical=False,
                    )
                        .sign(key, hashes.SHA256())
                )

                with open(cert_file, "wb") as f:
                    logpki.info('Writing cert file to {}'.format(cert_file))
                    f.write(cert.public_bytes(serialization.Encoding.PEM))
            except Exception as e:
                logpki.error("Exception while writing cert/key file: {}".format(e))
        else:
            logpki.error("Destination folder {} not found".format(destpath))
            return


    def rotate_cert(self, newcert, newkey):
        """
        Rotate the application cert with the new cert thumb print.
        :param newcert: New cert file path
        :param newkey: new key file path
        :return:
        """
        if all([os.path.isfile(newcert), os.path.isfile(newkey)]):
            try:
                with open(newcert) as f:
                    cert_str = f.read()
                    cert_binary = base64.b64encode(cert_str.encode('ascii')).decode('ascii')

            except Exception as e:
                logpki.error('Exception while getting cert cert/key - {}'.format(e))
                return False

            jwt = self.get_jwt(keyfile=cert['cert_key_path'])

            rotate_dict = {
                'keyCredential': {
                    'type': 'AsymmetricX509Cert',
                    'usage': 'Verify',
                    'key': cert_binary
                },
                'passwordCredential': None,
                'proof': jwt
            }

            return rotate_dict

        else:
            logpki.error('Certfile and Certkey file pah is not found. Exiting..')
            return False


    def cert_thumbprint(self, certfile):
        """
        get the thumbprint from the cet file
        :param certfile:
        :return:
        """
        try:
            with open(certfile) as f:
                cert_file = f.read()
                cert_obj = load_pem_x509_certificate(data=bytes(cert_file, 'UTF-8'), backend=default_backend())
                thumbprint = (cert_obj.fingerprint(hashes.SHA1()).hex())
            return thumbprint
        except Exception as e:
            logpki.error('Exception was thrown while reading cert file - {}'.format(e))
            return False


    def get_jwt(self, keyfile):
        """
        Generate a JWT token
        :param keyfile:
        :return:
        """
        with open(keyfile) as f:
            key_file = f.read()

        time_now = datetime.datetime.utcnow()

        claims_dict = {
            'aud': '00000002-0000-0000-c000-000000000000',
            'iss': config['client_id'],
            'nbf': time_now,
            'exp': time_now + datetime.timedelta(minutes=10)
        }

        encoded_jwt = jwt.encode(claims_dict, key_file, algorithm="RS256")

        return encoded_jwt
    
    # def app_add_cert(self, certfile, keyfile, appid=None):
    #     """
    #     Add a new cert to the application in AAD
    #     :param certfile: new cert file path
    #     :param keyfile: new keyfile path
    #     :return:
    #     """
    #
    #     if all([os.path.isfile(certfile), os.path.isfile(keyfile)]):
    #         data_dict = self.rotate_cert(newcert=certfile, newkey=keyfile)
    #         if not data_dict:
    #             logpki.error('Unable to get new cert_dict')
    #             return False
    #     else:
    #         logpki.error('Unable to find either certfile or keyfile path. Exiting')
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
    #             logpki.info('Add cert result code: {}'.format(result.status_code))
    #         else:
    #             logpki.error('Add cert result code: {}'.format(result.status_code))
    #         return result
    #
    #     except Exception as e:
    #         logpki.error('Exception {} while adding cert to app "{}"'.format(e, config['client_id']))
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
    #     jwt = self.get_jwt(keyfile=cert['cert_key_path'])
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
    #             logpki.info('Remove cert result code: {}'.format(result.status_code))
    #         else:
    #             logpki.error('Remove cert result code: {}'.format(result.status_code))
    #         return result
    #
    #     except Exception as e:
    #         logpki.error('Exception {} while deleting cert id "{}"'.format(e, certid))
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
    #             logpki.error('Unable to find app reg matching clientid {}'.format(clientid))
    #             return False
    #
    #         else:
    #             logpki.error('Get apps result: {}'.format(result.status_code))
    #             return False
    #
    #     except Exception as e:
    #         logpki.error('Exception {} while getting app reg object id:"{}"'.format(e, config['app_id']))
    #         return False
    #
    # def rotate_this_cert(self, days=30, force=False):
    #     """
    #     Check the cert used by this app. If it is close to expire, rotate
    #     :param days: Number days remaining in the cert before it is rotated
    #     :return:
    #     """
    #     # Get cert thumb print
    #     this_cert_thumbprint = self.cert_thumbprint(cert['cert_path']).upper()
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
    #         logpki.error('Did not find a matching cert in app reg. Exiting')
    #         return
    #
    #     exp_time = datetime.datetime.strptime(this_cert['endDateTime'], '%Y-%m-%dT%H:%M:%SZ')
    #     now_time = datetime.datetime.now()
    #     diff_time = exp_time - now_time
    #
    #     if not force:
    #         if diff_time.days <= days:
    #             logpki.warning('Current cert validity remaining days: {}'.format(diff_time.days))
    #             logpki.warning('Current cert will be rotated')
    #         else:
    #             logpki.info('Current cert is still valid. Remaining days: {}'.format(diff_time.days))
    #             return
    #     else:
    #         logpki.info('Forced cert rotation requested. Will proceed to rotate cert.')
    #
    #     # if close to expire, generate new cert
    #     logpki.info('Generating new cert and key files')
    #     cert_dir = os.path.split(cert['cert_path'])[0]
    #     cer_prefix = datetime.datetime.strftime(now_time, '%Y%m%d-%H%M%S')
    #     self.create_self_signed(cn=this_app['displayName'], destpath=cert_dir)
    #
    #     new_cert_path = os.path.join(cert_dir, this_app['displayName'] + '_cert.pem')
    #     new_key_path = os.path.join(cert_dir, this_app['displayName'] + '_key.pem')
    #
    #     if not all([os.path.isfile(new_cert_path), os.path.isfile(new_key_path)]):
    #         logpki.error('Did not find new cert/key generated in path {}'.format(cert_dir))
    #         return
    #
    #     # Add new cert to app
    #     logpki.info('Adding the new cert to app client_id:{}'.format(config['client_id']))
    #     resp = self.app_add_cert(certfile=new_cert_path, keyfile=new_key_path, appid=this_app['id'])
    #     if not resp:
    #         logpki.error('Failed to add the new cert to app clinet_id:{}. exiting..'.format(config['client_id']))
    #         return
    #
    #     # Rename cert files
    #     logpki.info('Renaming cert files..')
    #     bak_cert_fname = cert['cert_path'] + '.' + cer_prefix
    #     bak_key_fname = cert['cert_key_path'] + '.' + cer_prefix
    #     logpki.info('Renaming old cert file {} to {}'.format(cert['cert_path'], bak_cert_fname))
    #     os.rename(cert['cert_path'], bak_cert_fname)
    #
    #     logpki.info('Renaming old key file {} to {}'.format(cert['cert_key_path'], bak_key_fname))
    #     os.rename(cert['cert_key_path'], bak_key_fname)
    #
    #     logpki.info('Renaming new cert file {} to {}'.format(new_cert_path, cert['cert_path']))
    #     os.rename(new_cert_path, cert['cert_path'])
    #
    #     logpki.info('Renaming new key file {} to {}'.format(new_key_path, cert['cert_key_path']))
    #     os.rename(new_key_path, cert['cert_key_path'])
    #
    #     # remove old cert from app
    #     logpki.info('Removing old cert keyid {} from app client_id:{}'.format(this_cert['keyId'], config['client_id']))
    #     resp = self.app_remove_cert(certid=this_cert['keyId'], appid=this_app['id'])
    #     if not resp:
    #         logpki.error('Removing cert failed..')
    #     elif int(resp.status_code) == 204:
    #         logpki.info('Successfully deleted old cert keyid:{} from app client_id:{}'.format(this_cert['keyId'],
    #                                                                                           config['client_id']))
    #     else:
    #         logpki.error('Removing old cert failed with status code {}'.format(resp.status_code))