from subprocess import check_output, DEVNULL
import json

def get_adgroupmember(groupname):
    """
    get ad group members
    :param groupname:
    :return:
    """
    ps_arg = 'convertto-json(get-adgroupmember {})'.format(groupname)
    cmd_out = check_output(['powershell',ps_arg])
    cmd_out_dict = json.loads(cmd_out)
    return cmd_out_dict
