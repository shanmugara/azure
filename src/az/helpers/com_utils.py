"""Common utils lib"""
import os
from datetime import datetime
import platform
from github import Github
import base64
import urllib
import io

from az.helpers import my_logger

if platform.system().lower() == 'windows':
    LOG_DIR = os.path.join('c:\\', 'logs', 'azgraph')
else:
    LOG_DIR = os.path.join(os.environ['VIRTUAL_ENV'], 'logs', 'azgraph')

utillog = my_logger.My_logger(logdir=LOG_DIR, logfile='com_utils')


def write_out_file(outdir, filename, outlines):
    """
    Write the outfile to newfile, if file exisits rename old file to renfile
    :param newfile: new file name
    :param renfile: renamed file name for existing file
    :param outlines: file data
    :return:
    """
    epoch_now = str(int((datetime.now()).timestamp()))
    fname, ext = os.path.splitext(filename)

    if os.path.isdir(outdir):
        outfile_csv = os.path.join(outdir, filename)

        if os.path.isfile(outfile_csv):
            ren_file_name = os.path.join(outdir, '{}_{}{}'.format(fname, epoch_now, ext))
            utillog.info('Renaming old file to {}'.format(ren_file_name))
            os.rename(outfile_csv, ren_file_name)

        with open(outfile_csv, 'w') as f:
            utillog.info('Writing report file {}'.format(outfile_csv))
            f.writelines(outlines)

    else:
        utillog.error('Unable to find target dir "{}"'.format(outdir))


def github_get_file(base_url, repo, path, git_token, branch="main"):
    try:
        if any([not base_url, base_url == 'https://api.github.com']):
            git_url = 'https://api.github.com'
        else:
            git_url = f'{base_url}/api/v3'

        g = Github(base_url=git_url, login_or_token=git_token)
        repo = g.get_repo(repo)
        content_encoded = repo.get_contents(urllib.parse.quote(path), ref=branch).content
        content = base64.b64decode(content_encoded)
        content_str = content.decode()
        f_mem = io.StringIO(content_str)
        return f_mem
    except Exception as e:
        utillog.error(f'Exception was thorwn while connecting to github - {e}')
        return False
