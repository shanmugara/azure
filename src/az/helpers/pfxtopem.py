"""
A module to extract cert and key from a PFX file.
"""
from contextlib import contextmanager
from pathlib import Path
from tempfile import NamedTemporaryFile

import requests
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates


@contextmanager
def pfx_to_pem(pfx_path, pfx_password):
    ''' Decrypts the .pfx file to be used with requests. '''
    print('step 1')
    pfx = Path(pfx_path).read_bytes()
    print('step 2')
    private_key, main_cert, add_certs = load_key_and_certificates(pfx, pfx_password.encode('utf-8'), None)

    cert_file_out = "mycertfile.pem"
    cert_key_out = "mycertkey.pem"

    with open(cert_key_out, 'wb') as pem_file:
        print('step 3')
        pem_file.write(private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
        for ca in add_certs:
            pem_file.write(ca.public_bytes(Encoding.PEM))

    with open(cert_file_out, 'wb') as pem_file:
        pem_file.write(main_cert.public_bytes(Encoding.PEM))


# HOW TO USE:
# with pfx_to_pem('foo.pem', 'bar') as cert:
#     requests.post(url, cert=cert, data=payload)