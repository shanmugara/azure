
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
    sku_list = ['EMSPREMIUM', 'OFFICESUBSCRIPTION', 'ENTERPRISEPACK', 'ENTERPRISEPREMIUM']
    parser = argparse.ArgumentParser(description="Azure Graph API runner")

    subparser = parser.add_subparsers(dest='command')
    parse_lic = subparser.add_parser('licence', help='Check licence data')
    parse_lic.add_argument('-g', '--guid', help='SKU guid', required=True, default=None)

    parser_mon = subparser.add_parser('monitor', help='Monitor free licence')
    parser_mon.add_argument('-t', '--threshold', help='Check threshold', required=False, type=int, default=4)
    parser_mon.add_argument('-s', '--skuname', help='SKU Part name of the product', required=True, choices=sku_list)

    group_sync = subparser.add_parser('groupsync', help='Sync AD group to cloud group')
    group_sync.add_argument('-a', '--adgroup', help='AD group name', required=True, type=str)
    group_sync.add_argument('-c', '--cloudgroup', help='Cloud group name', required=True, type=str)


    args = parser.parse_args()

    if args:
        aad = azureauth.AzureAd()
    else:
        return False

    if args.command == 'licence':
        aad.get_licences_all(guid=args.guid)
    elif args.command == 'monitor':
        aad.lic_mon(skuname=args.skuname, threshold=args.threshold)
    elif args.command == 'groupsync':
        aad.sync_group(adgroup=args.adgroup, clgroup=args.cloudgroup)

if __name__ == '__main__':
    main()

