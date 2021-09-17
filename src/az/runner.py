import argparse
import sys
import os

app_root = os.path.split(os.path.abspath(__file__))[0]
sys.path.insert(0, app_root)

from az.helpers import pki_helper
from az.helpers import aadiam
from az.helpers import aadcap


class Runner(object):
    """
    Main runner class
    """

    def __init__(self, iam=False, cap=False, sps=False, cert_auth=True, auto_rotate=False, days=30):
        self.pki = pki_helper.Cert()
        if iam:
            self.iam = aadiam.Aadiam(cert_auth=cert_auth, auto_rotate=auto_rotate, days=days)
        if cap:
            self.cap = aadcap.AadCa()


def main():
    """

    :return:
    """
    sku_list = [
        "EMSPREMIUM",
        "OFFICESUBSCRIPTION",
        "ENTERPRISEPACK",
        "ENTERPRISEPREMIUM",
        "EMS",
        "M365_INFO_PROTECTION_GOVERNANCE",
        "AAD_PREMIUM_P2",
        "OFFICE365_MULTIGEO",
    ]

    parser = argparse.ArgumentParser(description="Azure Graph API runner")

    subparser = parser.add_subparsers(dest="command")

    parse_pfx = subparser.add_parser(
        "pfxtopem", help="Extract PFX to cert and key files"
    )
    parse_pfx.add_argument(
        "-p", "--path", help="Full path to the pfx file", required=True
    )
    parse_pfx.add_argument(
        "-s", "--secret", help="Secret to open the pfx", required=True
    )

    parse_self_sign = subparser.add_parser("selfsign", help="Create a self signed cert")
    parse_self_sign.add_argument(
        "-p", "--path", help="Full path to the cert and key file", required=True
    )
    parse_self_sign.add_argument(
        "-n", "--cn", help="CN for the self signed cert", required=True
    )

    parse_certrotate = subparser.add_parser("certrotate", help="Rotate ceurrent cert and key. (self-signed cert only)")
    parse_certrotate.add_argument("-d", "--days", help="Remaining number of days before a cert is rotated", type=int,
                                  default=30)
    parse_certrotate.add_argument("-f", "--force", help="Force cert rotation regardless of validity",
                                  action="store_true")

    parse_rep = subparser.add_parser("report", help="Activation report")
    parse_rep.add_argument(
        "-d",
        "--dirpath",
        help="Directory path for output file",
        default="\\\\corp.bloomberg.com\\ny-dfs\\Ops\\InfoSys\\Systems Engineering\\Dropboxes\\O365Activations",
    )
    parse_rep.add_argument(
        "--userauth",
        help="Use username password auth instead of cert auth.",
        action="store_true",
    )
    parse_rep.add_argument(
        "--certrotate",
        help="Automatically rotate auth cert if close to expire.",
        action="store_true",
    )
    parse_rep.add_argument("--days", help="Remaining number of days before a cert is rotated", type=int, default=30)

    parser_mon = subparser.add_parser("monitor", help="Monitor free licence")
    parser_mon.add_argument(
        "-t", "--threshold", help="Check threshold", required=False, type=int, default=4
    )
    parser_mon.add_argument(
        "-p",
        "--percent",
        help="Check threshold percentage",
        required=False,
        default=None,
    )
    parser_mon.add_argument(
        "-s",
        "--skuname",
        help="SKU Part name of the product",
        required=True,
        choices=sku_list,
    )
    parser_mon.add_argument(
        "--userauth",
        help="Use username password auth instead of cert auth.",
        action="store_true",
    )
    parser_mon.add_argument(
        "--certrotate",
        help="Automatically rotate auth cert if close to expire.",
        action="store_true",
    )
    parser_mon.add_argument("--days", help="Remaining number of days before a cert is rotated", type=int, default=30)

    group_sync = subparser.add_parser("groupsync", help="Sync AD group to cloud group")
    group_sync.add_argument(
        "--userauth",
        help="Use username password auth instead of cert auth.",
        action="store_true",
    )
    group_sync.add_argument(
        "--certrotate",
        help="Automatically rotate auth cert if close to expire.",
        action="store_true",
    )
    group_sync.add_argument("--days", help="Remaining number of days before a cert is rotated", type=int, default=30)

    group_sync.add_argument(
        "-c", "--cloudgroup", help="Cloud group name", required=False, type=str
    )
    group_sync.add_argument(
        "-t",
        "--testmode",
        dest="testmode",
        help="Run in test mode, no writes",
        action="store_true",
    )
    group_sync.set_defaults(testmode=False)
    filename = group_sync.add_mutually_exclusive_group()
    filename.add_argument(
        "-a", "--adgroup", help="AD group name", required=False, type=str
    )
    filename.add_argument(
        "-f",
        "--filename",
        help="Input JSON file path to parse group names from",
        type=str,
    )

    git_sync = subparser.add_parser(name="groupsyncgit", help="Groupsync with json file from git repo")
    git_sync.add_argument(
        "--userauth",
        help="Use username password auth instead of cert auth.",
        action="store_true",
    )
    git_sync.add_argument(
        "--certrotate",
        help="Automatically rotate auth cert if close to expire.",
        action="store_true",
    )
    git_sync.add_argument("--days", help="Remaining number of days before a cert is rotated", type=int, default=30)
    git_sync.add_argument("-r", "--repo", help="git repo name", type=str, required=True)
    git_sync.add_argument("-o", "--token", help="Git API access toekn", type=str, required=True)
    git_sync.add_argument("-u", "--giturl", help="Git API URL", default="")
    git_sync.add_argument("-f", "--filepath", help="Relative path of the groups json file", required=True, type=str)
    git_sync.add_argument("-t", "--testmode", dest="testmode", help="Run in test mode, no writes", action="store_true")

    revoke_session = subparser.add_parser("revoke", help="Revoke user session")
    revoke_args = revoke_session.add_mutually_exclusive_group()
    revoke_args.add_argument("-u", "--upn", help="AAD UPN of the user to revoke session")
    revoke_args.add_argument("-f", "--filename", help="Filename with UPNs in CSV format for bulk operation")

    caconf = subparser.add_parser("caconf", help="Conditional Policy Management")
    caconf.add_argument("--userauth", help="Use username password auth instead of cert auth.", action="store_true")
    caconf_bak = caconf.add_argument_group(title="Backup options")
    caconf_bak.add_argument("-b", "--backup", help="Backup all conditional polices", action="store_true")
    caconf_bak.add_argument("-d", "--dir", help="Directory path for outfiles")

    caconf_rest = caconf.add_argument_group(title="Restore options")
    caconf_rest.add_argument("-r", "--restore", help="Restore the given config json file", action="store_true")
    caconf_rest.add_argument("-f", '--filename', help="Full path of the config file to restore")


    args = parser.parse_args()

    if args:
        if args.command in ["pfxtopem", "selfsign"]:
            runner = Runner()
            if args.command == "pfxtopem":
                runner.pki.pfx_to_pem(pfx_path=args.path, pfx_password=args.secret)
            elif args.command == "selfsign":
                runner.pki.create_self_signed(cn=args.cn, destpath=args.path)

        elif args.command in ["monitor", "groupsync", "groupsyncgit", "report", "certrotate", "revoke", "caconf"]:
            try:
                cert_auth = True if not args.userauth else False
            except AttributeError:
                cert_auth = True
            try:
                cert_rotate = True if args.certrotate else False
            except AttributeError:
                cert_rotate = False
            try:
                days = args.days
            except AttributeError:
                days = 30

            if args.command == "caconf":
                runner = Runner(cap=True, cert_auth=cert_auth, auto_rotate=cert_rotate, days=days)
            else:
                runner = Runner(iam=True, cert_auth=cert_auth, auto_rotate=cert_rotate, days=days)

            if args.command == "monitor":
                runner.iam.lic_mon(
                    skuname=args.skuname,
                    threshold=args.threshold,
                    percentage=args.percent,
                )
            elif args.command == "groupsync":
                if all([args.adgroup, args.cloudgroup]):
                    runner.iam.sync_group(
                        adgroup=args.adgroup,
                        clgroup=args.cloudgroup,
                        test=args.testmode,
                    )
                elif args.filename:
                    runner.iam.sync_group_json(filename=args.filename)

            elif args.command == "groupsyncgit":
                runner.iam.sync_group_git(repo=args.repo, filepath=args.filepath, token=args.token, git_url=args.giturl,
                                          test=args.testmode)

            elif args.command == "revoke":
                if args.upn:
                    runner.iam.revoke_session(userid=args.upn)
                elif args.filename:
                    runner.iam.revoke_sessions_blk(filename=args.filename)

            elif args.command == "report":
                runner.iam.report_license_activation(outdir=args.dirpath)
                runner.iam.report_onedrive_usage(outdir=args.dirpath)
                runner.iam.report_office_usage(outdir=args.dirpath)

            elif args.command == "certrotate":
                force = True if args.force else False
                runner.iam.rotate_this_cert(days=days, force=force)

            elif args.command == "caconf":
                if all([args.backup, args.dir]):
                    runner.cap.export_all_cap(outdir=args.dir)
                elif all([args.restore, args.filename]):
                    runner.cap.import_cap(filename=args.filename)


    else:
        return False


if __name__ == "__main__":
    main()
