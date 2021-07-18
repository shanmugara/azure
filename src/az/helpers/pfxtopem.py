"""
A module to extract cert and key from a PFX file.
"""
from contextlib import contextmanager
from pathlib import Path
import os
from tempfile import NamedTemporaryFile

import requests
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates


# @contextmanager
def pfx_to_pem(pfx_path, pfx_password):
    '''
    Decrypts the .pfx file to cert and key file
    :param pfx_path: pfx file path to extract
    :param pfx_password: password for pfx file
    '''

    pfx = Path(pfx_path).read_bytes()
    private_key, main_cert, add_certs = load_key_and_certificates(pfx, pfx_password.encode('utf-8'), None)

    out_dir = os.path.split(Path(pfx_path))[0]
    cert_file_out = os.path.join(out_dir,"mycertfile.pem")
    cert_key_out = os.path.join(out_dir, "mycertkey.pem")

    with open(cert_key_out, 'wb') as pem_file:
        print("*** Writing key file to {}".format(cert_key_out))
        pem_file.write(private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))


    with open(cert_file_out, 'wb') as pem_file:
        print("*** Writing cert file to {}".format(cert_file_out))
        pem_file.write(main_cert.public_bytes(Encoding.PEM))
        for ca in add_certs:
            pem_file.write(ca.public_bytes(Encoding.PEM))


# HOW TO USE:
# with pfx_to_pem('foo.pem', 'bar') as cert:
#     requests.post(url, cert=cert, data=payload)