from setuptools import setup
import os
from callgraph.helpers.__version__ import version

req_lst = ['requests','msal', 'PyGithub']
if os.name == 'nt':
    req_lst.append('colorama')

setup(name='azuregraph',
      version=version,
      description='Azure Graph API wrapper.',
      url='https://none.none',
      author='RP',
      author_email='speriyasamy@bloomberg.net',
      license='GPL',
      install_requires=req_lst,
      package_dir={"": "src"},
      packages=['callgraph', 'callgraph.helpers'],
      entry_points={
          'console_scripts':
              ['callgraph = callgraph.runner:main'],
      },
      include_package_data=True,
      zip_safe=False,
      )
