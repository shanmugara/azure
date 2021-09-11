"""
Config file to store Graph API connection information.
1. If you have a PFX file of your cert with key, run "callgraph pfxtopem -p inputfile -s secret" to extract cert/key
files.
2. If you need a self signed cert/key, run "callgraph selfsign -p outfilepath -c cn.for.the.cert"

"""
# users
# pygraph

# PROVIDE YOUR TENANCY NAME HERE (REQUIRED)
tenancy = ".onmicrosoft.com"

# UPDATE THIS DICT WITH CERT FILE AND CERT KEY FILE PATHS. SCOPE IS SET TO GRAPH API (DEFAULT)
cert = {
    "cert_key_path": r"/path/to_cert/mykey.pem",
    "cert_path": r"/path/to_cert/mycert.cer",
    "scope": "https://graph.microsoft.com/.default",
}

# UPDATE THIS DICT WITH USER NAME, PASSWORD CLIENT SECRET IF YOU USE USER AUTH INSTEAD OF CERT AUTH. SCOPE MUST INCLUDE ALL PERMISSIONS
# REQUIRED FOR THE USER ACCOUNT TO PERFORM THE TASKS. PASSWORD IS BYTES BASE64 ENCODED.
user = {
    "username": "",
    "password": b"",
    "scope": [
        "User.ReadWrite.All",
        "Reports.Read.All",
    ],
    "client_secret": "",
}

# THIS DICT APPLIES FOR BOTH USER AUTH AND CERT AUTH. UPDATE CLIENT_ID OF THE APP REG. SET PROXIES. CERT AUTH DEFAULT IS TRUE
# SET TO FALSE IF YOU WANT TO USE USER AUTH INSTEAD. YOU CAN ALSO OVERRIDE AUTH METHOD USING ARG PASSED TO CALLGRAPH RUNNER.
config = {
    "authority": "https://login.microsoftonline.com/{}".format(tenancy),
    "client_id": "",
    "apiurl": "https://graph.microsoft.com/v1.0",
    "apibetaurl": "https://graph.microsoft.com/beta",
    "cert_auth": True,
    "proxy": None,
    "github": "https://github.com"
}