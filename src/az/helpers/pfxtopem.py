"""
A module to extract cert and key from a PFX file.
"""
from pathlib import Path
import os
import platform
import sys
import base64

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
from . import my_logger
from .config import config, cert

if platform.system().lower() == 'windows':
    LOG_DIR = os.path.join('c:\\', 'logs', 'azgraph')
else:
    LOG_DIR = os.path.join(os.environ['VIRTUAL_ENV'], 'logs', 'azgraph')

log = my_logger.My_logger(logdir=LOG_DIR, logfile='certmod')


# @contextmanager
def pfx_to_pem(pfx_path, pfx_password):
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
            log.info("*** Writing key file to {}".format(cert_key_out))
            pem_file.write(
                private_key.private_bytes(
                    Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
                )
            )

        with open(cert_file_out, "wb") as pem_file:
            log.info("*** Writing cert file to {}".format(cert_file_out))
            pem_file.write(main_cert.public_bytes(Encoding.PEM))
            for ca in add_certs:
                pem_file.write(ca.public_bytes(Encoding.PEM))
    except Exception as e:
        log.error("Exception {} while writing out file".format(e))


def create_self_signed(cn, destpath):
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
                log.info('Writing key file to {}'.format(key_file))
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
                log.info('Writing cert file to {}'.format(cert_file))
                f.write(cert.public_bytes(serialization.Encoding.PEM))
        except Exception as e:
            log.error("Exception while writing cert/key file: {}".format(e))
    else:
        log.error("Destination folder {} not found".format(destpath))
        return


def rotate_cert(newcert, newkey):
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
            log.error('Exception while getting cert cert/key - {}'.format(e))
            return False

        jwt = get_jwt(keyfile=cert['cert_key_path'])

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
        log.error('Certfile and Certkey file pah is not found. Exiting..')
        return False


def cert_thumbprint(certfile):
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
        log.error('Exception was thrown while reading cert file - {}'.format(e))
        return False


def get_jwt(keyfile):
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
