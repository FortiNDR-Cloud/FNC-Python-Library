from setuptools import find_packages, setup

setup(
    name='com.fortinet.fndrc.integrations.python_client',
    version='1.0.4',
    packages=['fnc', 'fnc.api', 'fnc.metastream'],
    url='fortinet.com',
    license='',
    author='Fortinet',
    description='Classes and functions to interact with the FortiNDR Cloud APIs and Metastream.',
    long_description=open('README.md').read()
    # install_requires=['boto3 == 1.10.23']
)
