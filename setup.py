from setuptools import setup

setup(name='azuregraph',
      version="0.0.1",
      description='Azure Graph API wrapper.',
      url='https://none.none',
      author='MS',
      author_email='',
      license='GPL',
      install_requires=['requests',
                        ],
      packages=['qc', 'qc.common', 'qc.helpers', 'qc.appmodules', 'qc.appmodules.apache'],
      entry_points={
          'console_scripts':
              ['callgraph = .runner:main'],
      },
      include_package_data=True
      )
