"""
A module to extract cert and key from a PFX file.
"""
from pathlib import Path
import os

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
import datetime


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
            print("*** Writing key file to {}".format(cert_key_out))
            pem_file.write(
                private_key.private_bytes(
                    Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
                )
            )

        with open(cert_file_out, "wb") as pem_file:
            print("*** Writing cert file to {}".format(cert_file_out))
            pem_file.write(main_cert.public_bytes(Encoding.PEM))
            for ca in add_certs:
                pem_file.write(ca.public_bytes(Encoding.PEM))
    except Exception as e:
        print("Exception {} while writing out file".format(e))


def create_self_signed(cn, destpath):
    """
    Generate a self signed cert/key amd store in destpath
    :param cn: CN for cert
    :param destpath: destination path
    :return:
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if os.path.isdir(destpath):
        try:
            key_file = os.path.join(destpath, "{}_key.pem".format(cn))
            with open(key_file, "wb") as f:
                print('Wriring key file to {}'.format(key_file))
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
                .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=10))
                .add_extension(
                    x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
                    critical=False,
                )
                .sign(key, hashes.SHA256())
            )

            with open(cert_file, "wb") as f:
                print('Writing cert file to {}'.format(cert_file))
                f.write(cert.public_bytes(serialization.Encoding.PEM))
        except Exception as e:
            print("Exception while writing cert/key file: {}".format(e))
    else:
        print("Destination folder {} not found".format(destpath))
        return
