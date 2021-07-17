import argparse
import sys
import os

app_root = os.path.split(os.path.abspath(__file__))[0]
sys.path.insert(0, app_root)

from az.rest import azureauth


def main():
    """

    :return:
    """
    sku_list = ['EMSPREMIUM', 'OFFICESUBSCRIPTION', 'ENTERPRISEPACK', 'ENTERPRISEPREMIUM', 'EMS',
                'M365_INFO_PROTECTION_GOVERNANCE', 'AAD_PREMIUM_P2', 'OFFICE365_MULTIGEO']

    parser = argparse.ArgumentParser(description="Azure Graph API runner")

    subparser = parser.add_subparsers(dest='command')
    parse_lic = subparser.add_parser('licence', help='Check licence data')
    parse_lic.add_argument('-g', '--guid', help='SKU guid', required=True, default=None)

    parse_rep = subparser.add_parser('report', help='Activation report')
    parse_rep.add_argument('-d', '--dirpath', help='Directory path for output file',
                           default="\\\\corp.bloomberg.com\\ny-dfs\\Ops\\InfoSys\\Systems Engineering\\Dropboxes\\O365Activations")

    parser_mon = subparser.add_parser('monitor', help='Monitor free licence')
    parser_mon.add_argument('-t', '--threshold', help='Check threshold', required=False, type=int, default=4)
    parser_mon.add_argument('-p', '--percent', help='Check threshold percentage', required=False, default=None)
    parser_mon.add_argument('-s', '--skuname', help='SKU Part name of the product', required=True, choices=sku_list)

    group_sync = subparser.add_parser('groupsync', help='Sync AD group to cloud group')
    group = group_sync.add_mutually_exclusive_group()
    group.add_argument('-a', '--adgroup', help='AD group name', required=False, type=str)
    group.add_argument('-c', '--cloudgroup', help='Cloud group name', required=False, type=str)
    group.add_argument('-t', '--testmode', dest='testmode',help='Run in test mode, no writes', action='store_true')
    group.set_defaults(testmode=False)
    filename = group_sync.add_mutually_exclusive_group()
    filename.add_argument('-f', '--filename', help='Input JSON file path to parse group names from', type=str)

    args = parser.parse_args()

    if args:
        aad = azureauth.AzureAd()
    else:
        return False

    if args.command == 'licence':
        aad.get_licences_all(guid=args.guid)
    elif args.command == 'monitor':
        aad.lic_mon(skuname=args.skuname, threshold=args.threshold, percentage=args.percent)
    elif args.command == 'groupsync':
        aad.sync_group(adgroup=args.adgroup, clgroup=args.cloudgroup, test=args.testmode)
    elif args.command == 'report':
        aad.report_license_activation(outdir=args.dirpath)


if __name__ == '__main__':
    main()
