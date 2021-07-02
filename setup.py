from setuptools import setup

setup(name='azuregraph',
      version="0.0.1",
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
      entry_points={
          'console_scripts':
              ['callgraph = src.runner:main'],
      },
      include_package_data=True,
      zip_safe=False,
      )
