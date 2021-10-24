from setuptools import setup
import os

req_lst = ['requests','msal', 'PyGithub']
if os.name == 'nt':
    req_lst.append('colorama')

setup(name='callgraph',
      version="0.0.10",
      description='Azure Graph API wrapper.',
      url='https://none.none',
      author='RP',
      author_email='speriyasamy@',
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
