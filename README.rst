Vault 12factor and Django integration
=====================================

This project provides helper classes for integrating
`Hashicorp Vault <https://vaultproject.io/>`__ with your Python projects and
Django.

**Please note that this is still under active development and APIs are subject
to change.**


Installation
------------
This has been uploaded to the Cheeseshop aka Pypi as
`12factor-vault <https://pypi.python.org/pypi/12factor-vault>`__. So just add
``12factor-vault`` to your ``requirements.txt`` or ``setup.py``.

``pip install 12factor-vault`` also works.


Environment variables
+++++++++++++++++++++
===========================  =========================  ==================================
Environment Variable         Vault auth backend         Direct configuration static method
                                                        on BaseVaultAuthenticator
===========================  =========================  ==================================
VAULT_TOKEN                  Token authentication       token(str)
VAULT_APPID, VAULT_USERID    App-id authenticaion       app_id(str, str)
VAULT_SSLCERT, VAULT_SSLKEY  SSL Client authentication  ssl_client_cert(str, str)
===========================  =========================  ==================================

Approle authentication will be easily added once the fix in `hvac#115
<https://github.com/ianunruh/hvac/pull/115>`__ has been released.

The Django example below uses the following environment variables:

===========================  ==================================================
Environment Variable         Description
===========================  ==================================================
VAULT_DATABASE_PATH          The path to Vault's credential-issuing backend
VAULT_CA                     The CA issuing Vault's HTTPS SSL certificate (for
                             CA pinning)
DATABASE_NAME                Name of the database to connect to on the database
                             server.
DATABASE_OWNERROLE           The PostgreSQL role to use for ``SET ROLE`` after
                             connecting to the database
===========================  ==================================================

General usage
-------------
Basically after configuring a ``BaseVaultAuthenticator`` instance which creates
authenticated Vault clients (relying on the excellent
`hvac library <https://github.com/ianunruh/hvac>`__) you can use that to create
``VaultCredentialProvider`` instances which manage leases and renew credentials
as needed (e.g. database credentials managed by one of Vault's *secrets*
backends).

``VaultAuth12Factor`` is a subclass of ``BaseVaultAuthenticator`` that reads
all necessary configuration from environment variables.


Django
------
Integrating with Django requires a small monkeypatch that retries failed
database connections after refreshing the database credentials from Vault. The
``vault12factor`` Django App will install that patch automatically. You also
have to wrap your database settings dict in a
``DjangoAutoRefreshDBCredentialsDict`` instance that knows hot to refresh
database credentials from Vault.

``vault12factor`` will check if an instance of
``DjangoAutoRefreshDBCredentialsDict`` is configured in ``settings.DATABASES``
before monkey-patching Django. So if you want to use ``vault12factor`` but
configure your databases in separate Django apps or other things that this code
can't detect, you will want to call ``vault12factor.monkeypatch_django()``
yourself.

Here is an example for integrating this with Django, using Vault to get
database credentials. When using PostgreSQL you will also want to look at
`django-postgresql-setrole <https://github.com/jdelic/django-postgresql-setrole>`__.

.. code-block:: python

    # in settings.py
    from vault12factor import \
        VaultCredentialProvider, \
        VaultAuth12Factor, \
        DjangoAutoRefreshDBCredentialsDict

    INSTALLED_APPS += ['vault12factor',]

    if DEBUG and not VaultAuth12Factor.has_envconfig():
        SECRET_KEY = "secretsekrit"  # FOR DEBUG ONLY!
        DATABASES = {
            'default': {
                'ENGINE': 'django.db.backends.sqlite3',
                'NAME': 'authserver.sqlite3',
            }
        }
    else:
        if DEBUG:
            SECRET_KEY = "secretsekrit"  # FOR DEBUG ONLY!

        VAULT = VaultAuth12Factor.fromenv()
        CREDS = VaultCredentialProvider("https://vault.local:8200/", VAULT,
                                        os.getenv("VAULT_DATABASE_PATH",
                                        "db-mydatabase/creds/fullaccess"),
                                        os.getenv("VAULT_CA", None), True,
                                        DEBUG)

        DATABASES = {
            'default': DjangoAutoRefreshDBCredentialsDict(CREDS, {
                'ENGINE': 'django.db.backends.postgresql',
                'NAME': os.getenv("DATABASE_NAME", "mydatabase"),
                'USER': CREDS.username,
                'PASSWORD': CREDS.password,
                'HOST': '127.0.0.1',
                'PORT': '5432',
                # requires django-postgresql-setrole
                'SET_ROLE': os.getenv("DATABASE_OWNERROLE", "mydatabaseowner")
            }),
        }


License
=======

Copyright (c) 2016-2017, Jonas Maurus
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
   may be used to endorse or promote products derived from this software
   without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
