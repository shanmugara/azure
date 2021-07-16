from setuptools import setup
import os

req_lst = ['requests','msal']
if os.sys.platform == 'win32':
    req_lst.append('colorama')

setup(name='azuregraph',
      version="0.0.2",
      description='Azure Graph API wrapper.',
      url='https://none.none',
      author='RP',
      author_email='speriyasamy@',
      license='GPL',
      install_requires=[
          'requests',
          'msal',
      ],
      package_dir={"": "src"},
      packages=['az','az.rest', 'az.helpers'],
      entry_points={
          'console_scripts':
              ['callgraph = az.runner:main'],
      },
      include_package_data=True,
      zip_safe=False,
      )
