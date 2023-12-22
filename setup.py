from setuptools import setup

setup(
    name='com.fortinet.fndrc.integrations.metastream',
    version='1.3.0',
    packages=['metastream'],
    url='fortinet.com',
    license='',
    author='Fortinet',
    author_email='srohde@gigamon.com',
    description='Functions for fetching events from FortiNDR Cloud Metastream.',
    long_description=open('README.md').read(),
    # install_requires=['boto3 == 1.10.23']
)
