from setuptools import find_packages, setup

setup(
    name='com.fortinet.fndrc.integrations.python_client',
    version='1.0.0',
    packages=['fnc.api', 'fnc.metastream'],
    url='fortinet.com',
    license='',
    author='Fortinet',
    author_email='emesabarrameda@fortinet.com',
    description='Classes and functions to interact with the FortiNDR Cloud APIs and Metastream.',
    long_description=open('README.md').read()
    # install_requires=['boto3 == 1.10.23']
)
