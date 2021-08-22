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
hidden
```


## Install the graphapi python package ##

1. The `graphapi` package is not yet published in artifactory PyPi. So you can install the package by
downloading the sdist package from the bbgit repo.
   
2. Download `https://github.com/shanmugara/azure/blob/master/dist/azuregraph-0.0.3.tar.gz` to your host
where the package is to be installed.
   
3. Make sure the `c:\python\venv\graphapi` venv is activated.
4. Install the package by running `pip install azuregraph-0.0.3.tar.gz`. This will install the grpahapi
package and all its dependencies.
   
5. You can verify the installed packages with `pip list`.

6. Next we configure the CA trust and connection properties for the graph api.

## Add BLP CA cert to Python trust ##

1. All connections to Azure grpah api traverse an SSL proxy, and the certs are replaced by an
SSL intercept cert issued by . In order for the Python `requests` to trust this cert, we need to add
   it to Py cert trust.
   
2. Edit `c:\python\venv\graphapi\lib\site-packages\certifi\cacert.pem`.
3. Add the following certificate content at the end of the `cacert.pem` file:
```# 
cert is hidden
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

<b>tenancy = "tenancyname.onmicrosoft.com"</b>

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
    "proxy": {'http': 'proxy.domain.com:81', 'https': 'proxy.domain.com:81'},
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


# Certificate rotation #

The code supports automatically rotating certificates in the registered app in AAD. The certificate rotation function **supports 
only self-signed** certs as of now.

## Rotating cert as part of callgraph commands ##

The cert can be rotated automatically while calling any **callgraph** command, such as **groupsync, report or monitor**.
In order to rotate the cert during these commands, pass teh following additional args:

   `c:\python\venv\graphapi\scripts\callgraph.exe groupsync -f c:\path\to\filename.json --certrotate --days=30`

The above **groupsync** call will check the validity of the current certificate, and if its validity is **less than or equal to 30
days**, the certificate will be rotated. A new self-signed cert is generated, and replaces the old cert in the registered app in AAD 
and in Python venv. The old cert is also removed from the registered app in AAD. The `--days` defaults to **30** if not specified.

## Forcing a certificate rotation on-demand ##

You can force the certificate to be rotated on-demand using the following **callgraph** commands:

   `c:\python\venv\graphapi\scripts\callgraph.exe certrotate`
   This command will rotate the cert if its validity is less than or equal to **30 days** (default).

   `c:\python\venv\graphapi\scripts\callgraph.exe certrotate --days=60`
   This command will rotate the cert if its validity is less than or equal to **60 days**.

   `c:\python\venv\graphapi\scripts\callgraph.exe certrotate -f`
   This command will rotate the cert **immediately**, regardless of the remaining validity period.





