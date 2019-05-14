"""A setuptools based setup module.
See:
https://packaging.python.org/en/latest/distributing.html
https://github.com/pypa/sampleproject
"""

from setuptools import setup, find_packages
from os import path
from io import open

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='asym_crypto_yaml',  # Required
    version='0.0.6',  # Required
    packages=find_packages(exclude=['contrib', 'docs', 'tests']),  # Required
    python_requires=">=3.6",
    include_package_data=True,
    install_requires=[
    	'pyyaml',
        'cryptography',
        'click',
    ],
    entry_points='''
        [console_scripts]
        asym_crypto_yaml=scripts.asym_crypto_yaml:cli
    ''',
)
