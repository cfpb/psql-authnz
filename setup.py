from setuptools import setup

setup(name='psql-authnz',
      version='0.1',
      description='Synchronize PostgreSQL roles with LDAP groups.',
      url='http://github.com/cfpb/psql-authnz',
      author='Tim Anderegg',
      author_email='timothy.anderegg@gmail.com',
      license='CC0',
      packages=['psql_authnz'],
      entry_points={
        'console_scripts': [
            'psql-authnz=psql_authnz.psql_authnz:main'
        ]
      })
