from subprocess import check_output
import os

app_root = os.path.split(os.path.abspath(__file__))[0]

def get_adgroupmember(groupname):
    """
    get ad group members
    :param groupname:
    :return:
    """
    cmd = os.path.join(app_root, 'admodule.ps1')
    cmd_out = check_output(['powershell','-c',cmd,'-groupname',groupname])
    mems_lines = cmd_out.decode().splitlines()

    return mems_lines
