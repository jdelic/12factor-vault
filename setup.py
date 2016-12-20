#!/usr/bin/env python
# -* encoding: utf-8 *-
import os
from setuptools import setup

HERE = os.path.dirname(__file__)

try:
    long_description = open(os.path.join(HERE, 'README.rst')).read()
except IOError:
    long_description = None


setup(
    name="12factor-vault",
    version="0.1.7",
    packages=["vault12factor"],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Programming Language :: Python :: 3 :: Only",
        "License :: OSI Approved :: BSD License",
        "Operating System :: POSIX",
    ],
    url="https://github.com/jdelic/12factor-vault/",
    author="Jonas Maurus (@jdelic)",
    author_email="jonas-12factor-vault@gopythongo.com",
    maintainer="GoPythonGo.com",
    maintainer_email="info@gopythongo.com",
    description="Helper classes to integrate Django and other projects with Vault",
    long_description=long_description,
)
