from setuptools import setup
import os

req_lst = ['requests','msal']
if os.name == 'nt':
    req_lst.append('colorama')

setup(name='azuregraph',
      version="0.0.7",
      description='Azure Graph API wrapper.',
      url='https://none.none',
      author='RP',
      author_email='speriyasamy@',
      license='GPL',
      install_requires=req_lst,
      package_dir={"": "src"},
      packages=['az', 'az.helpers'],
      entry_points={
          'console_scripts':
              ['callgraph = az.runner:main'],
      },
      include_package_data=True,
      zip_safe=False,
      )
