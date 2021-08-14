# BLP Azure Graph API Python wrapper #

![](https://badges.dev.bloomberg.com/badge/python/3.6/blue?icon=python)
![](https://badges.dev.bloomberg.com/badge/python/3.7/blue?icon=python)
![](https://badges.dev.bloomberg.com/badge/python/3.8/blue?icon=python)

A Python wrapper module using MSAL library for authentication, and Graph REST API calls to manage Azure.

## Setting up your Python venv ##
1. This azure graph API package can run either on Windows or Linux platform. Keep in mind the 
groupsync function will only run in a Windows platform due to dependencies to get groups from
   on-prem active directory.
   
2. Install Python 3.x.x to C:\Python\3.x.x folder.
3. Under `C:\Python` create a folder `C:\Python\venv` to store the venv.
4. Run `C:\Python\3.x.x\python.exe -m venv c:\python\venv\graphapi`. 
5. Once the venv is created activate the venv, by running `C:\python\venv\graphapi\scripts\activate.ps1`.
6. Create a `pip.ini` file so that we can use artifactory pypi to install required modules.
7. Create `C:\python\venv\graphapi\pip.ini` with following content:

```
[global]
retries = 0
timeout = 15

# our own wheel repo
# [ose]
index-url = https://artifactory.inf.bloomberg.com/artifactory/api/pypi/bloomberg-pypi-ose/simple

trusted-host = artifactory.inf.bloomberg.com
# Don't check if pip needs an upgrade every time we install something with pip
disable-pip-version-check = true
disable-cache = true

[list]
format = columns

[search]
index = https://artifactory.inf.bloomberg.com/artifactory/api/pypi/bloomberg-pypi-ose/simple
```


## Install the graphapi python package ##

1. The `graphapi` package is not yet published in artifactory PyPi. So you can install the package by
downloading the sdist package from the bbgit repo.
   
2. Download `https://bbgithub.dev.bloomberg.com/speriyas/graphapi/blob/master/dist/azuregraph-0.0.3.tar.gz` to your host
where the package is to be installed.
   
3. Make sure the `c:\python\venv\graphapi` venv is activated.
4. Install the package by running `pip install azuregraph-0.0.3.tar.gz`. This will install the grpahapi
package and all its dependencies.
   
5. You can verify the installed packages with `pip list`.

6. Next we configure the BLP CA trust and connection properties for the graph api.

## Add BLP CA cert to Python trust ##

1. All connections to Azure grpah api traverse an SSL proxy, and the certs are replaced by an
SSL intercept cert issued by BLP. In order for the Python `requests` to trust this cert, we need to add
   it to Py cert trust.
   
2. Edit `c:\python\venv\graphapi\lib\site-packages\certifi\cacert.pem`.
3. Add the following certificate content at the end of the `cacert.pem` file:
```# Issuer: CN=Bloomberg LP CORP CLASS 1 ROOT G2 OU=NDIS O=Bloomberg LP L=NEW YORK S=NEW YORK C=US
# Subject: CN=Bloomberg LP CORP CLASS 1 ROOT G2 OU=NDIS O=Bloomberg LP L=NEW YORK S=NEW YORK C=US
# Serial: 00c8c0bfe9ec747b48
# MD5 Fingerprint: 51:e1:c2:e7:fe:4c:84:af:59:0e:2f:f4:54:6f:ea:29
# SHA1 Fingerprint: 9f:8e:c3:fb:d1:5a:c2:4e:74:93:95:a3:11:3c:92:eb:04:07:cc:00
-----BEGIN CERTIFICATE-----
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
ji7REaORPuzPOeED6PcvSbpong==
-----END CERTIFICATE-----
```
4. This enables Python `requests` to trust the `BLP CA`. 
5. Proceed to configuring connection options.

## Configure connection options for the tenancy ##

1. The azgraph package deploys a template `config.py` file as `C:\Python\venv\graphapi\Lib\site-packages\az\helpers\config_tmp.py`.
2. Rename this file to `config.py`.
3. Edit the file using `Python IDLE` or any editor that preserves formatting.
4. All <b>bolded keys</b> must be defined in order for the API connection to succeed.

<pre>
# PROVIDE YOUR TENANCY NAME HERE (REQUIRED)

<b>tenancy = "bloombergcorpdev.onmicrosoft.com"</b>

# UPDATE THIS DICT WITH CERT FILE AND CERT KEY FILE PATHS.
# SCOPE IS SET TO GRAPH API (DEFAULT)

cert = {
<b>    "cert_key_path": r"C:\path\path\my_key.pem", </b>
<b>    "cert_path": r"C:\path\path\my_cert.pem", </b>
    "scope": "https://graph.microsoft.com/.default",
}

# USER DICT IS NOT REQUIRED WHEN CERT AUTH IS USED.
# UPDATE THIS DICT WITH USER NAME, PASSWORD CLIENT SECRET IF YOU USE USER AUTH INSTEAD OF CERT AUTH. SCOPE MUST INCLUDE ALL PERMISSIONS
# REQUIRED FOR THE USER ACCOUNT TO PERFORM THE TASKS. PASSWORD IS BYTES BASE64 ENCODED.
user = {
    "username": "",
    "password": b"",
    "scope": ["User.Read"],
    "client_secret": "",
}

# THIS DICT APPLIES FOR BOTH USER AUTH AND CERT AUTH. UPDATE CLIENT_ID OF THE APP REG. SET PROXIES. CERT AUTH DEFAULT IS TRUE
# SET TO FALSE IF YOU WANT TO USE USER AUTH INSTEAD. YOU CAN ALSO OVERRIDE AUTH METHOD USING ARG PASSED TO CALLGRAPH RUNNER.
config = {
    "authority": "https://login.microsoftonline.com/{}".format(tenancy),
<b>    "client_id": "", </b>
    "apiurl": "https://graph.microsoft.com/v1.0",
    "cert_auth": True,
    "proxy": {'http': 'proxy.bloomberg.com:81', 'https': 'proxy.bloomberg.com:81'},
}
</pre>

5. Once the `config.py` is defined, you are ready to test the connection.

## Testing your authentication ##

1. Run the command `c:\python\venv\graphapi\scripts\callgraph.exe groupsync` without any args.
2. If the authentication worked, you should see the following logs:
```angular2html
[INFO]: Current Azure tenancy: bloombergcorpdev.onmicrosoft.com
[INFO]: Obtaining new auth token by certificate and key pair
[INFO]: Successfully obtained auth token.
```
3. If you you did not get an auth token, verify your settings again.
4. If you need a self signed cert for testing, or if you need to extract cert/key from a Windows cert store,
see the following sections.

## How to create a self-signed cert using this library ##

This module has a method to create a self-signed certificate and key for testing your connection 
to graph api. You should always use a cert issued by a trusted CA for production when possible.

1. To create a self-signed cetificate/key, run `c:\python\venv\graphapi\scripts\callgraph.exe selfsign -p 
   path_to_the_cert -n cn.of.your.cert`.
   
2. This will create a cert file named `cn.of.your.cert_cert.pem` and key file `cn.of.your.cert_key.pem`
in the path your specified.
   
3. You can upload the cert to Azure registered application to enable authentication using this cert/key pair.


## How to extract cert file and key from a PKCS#12 container using this library ##

In Windows platform, if you have a signed cert from a CA, you can extract the cert and key using a PKCS#12 container file (.pfx).

1. First export your cert and private key to a .pfx file using `certlm.msc`. 

2. To extract the cert and key from the `.pfx` run this command `c:\python\venv\graphapi\scripts\callgraph.exe pfxtopem
   -p path_to_your_pfx_file -s pfxpassword`
   
3. This will extract 2 files, `mycertfile.pem` and `mycertkey.pem` to the same path as the `.pfx` file.
4. You can rename these files, and upload the cert file to Azure registered app to enable authentication using this
cert/key pair.


# Group Sync #
## Pre-requisites ##
This library provides a method to take the members of an on-prem AD group, direct and indirect
members, and add them to a Azure cloud security group. Any members not in the on-prem AD group will
automatically be removed from the Azure cloud security group. In order to use this function, the
host running this library, must meet these requirements.

1. Create a Python venv as described above and install the module package.
2. Install `One Idendity ARS PowerShelll add-in` module, as we rely on this module to extract
on-prem AD group members.
   
## Running groupsync ##

1. To sync a single on-prem AD group to a Azure cloud security group, run the following command:

`c:\python\venv\graphapi\scripts\callgraph.exe groupsync -a on_prem_ad_group_name -c cloud_group_name`.
   
2. You can sync multiple on-prem AD groups to multiple cloud groups, by using a JSON file input. Create a JSON file
with following format:
```angular2html
{
    "myadgroup1": "mycloudgroup1",
    "myadgroup2": "mycloudgroup2"
}
```
In this JSON, we want to sync on prem group `myadgroup1` to cloud group `mycloudgroup1`, and on-prem group `myadgroup2`
to `mycloudgroup2`

3. To run the group sync with JSON file input, run the following command, 
   
   `c:\python\venv\graphapi\scripts\callgraph.exe groupsync -f c:\path\to\filename.json`
   
   This will sync each group pair to Azure AD.
   
4. You can run the `groupsync` in `test mode` to see what changes will be applied without actually making the changes.
To run in test mode, include `-t` arg, as in:
   
`c:\python\venv\graphapi\scripts\callgraph.exe groupsync -a on_prem_ad_group_name -c cloud_group_name -t` 

OR

`c:\python\venv\graphapi\scripts\callgraph.exe groupsync -f c:\path\to\filename.json -t`
   


