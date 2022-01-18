from subprocess import check_output
import os
import functools
import timeit
import platform

app_root = os.path.split(os.path.abspath(__file__))[0]

from callgraph.helpers import my_logger

if platform.system().lower() == 'windows':
    LOG_DIR = os.path.join('c:\\', 'logs', 'azgraph')
else:
    LOG_DIR = os.path.join(os.environ['VIRTUAL_ENV'], 'logs', 'azgraph')

log = my_logger.My_logger(logdir=LOG_DIR, logfile='powershell')


def add_timer(func):
    functools.wraps(func)

    def timed_func(*args, **kwargs):  # Inner func return func
        start_time = timeit.default_timer()
        func_results = func(*args, **kwargs)
        end_time = timeit.default_timer()
        elapsed_time = end_time - start_time
        log.info(
            "Function {} - Elapsed time: {}".format(
                func.__name__, round(elapsed_time, 3)
            )
        )
        return func_results

    return timed_func


@add_timer
def get_adgroupmember(groupname):
    """
    get ad group members
    :param groupname:
    :return:
    """
    cmd = os.path.join(app_root, 'admodule.ps1')
    cmd_out = check_output(
        ['powershell', '-executionpolicy', 'bypass', '-noprofile', '-c', cmd, '-groupname', groupname])
    mems_lines = cmd_out.decode().splitlines()
    if 'failed_to_get_members' in mems_lines:
        mems_lines = False

    return mems_lines
