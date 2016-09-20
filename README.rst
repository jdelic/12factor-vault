Vault 12factor and Django integration
=====================================

This project provides helper classes for integrating
`Hashicorp Vault <https://vaultproject.io/>`__ with your Python projects and
Django.


Installation
------------
This has been uploaded to the Cheeseshop aka Pypi as
`12factor-vault <https://pypi.python.org/pypi/12factor-vault>`__. So just add
`12factor-vault` to your `requirements.txt` or `setup.py`.

`pip install 12factor-vault` also works.


General usage
-------------
Basically after configuring a `BaseVaultAuthenticator` instance which creates
authenticated Vault clients (relying on the excellent
`hvac library <https://github.com/ianunruh/hvac>`__) you can use that to create
`VaultCredentialProvider` instances which manage leases and renew credentials
as needed (e.g. database credentials managed by one of Vault's *secrets*
backends).

`VaultAuth12Factor` is a subclass of `BaseVaultAuthenticator` that reads
all necessary configuration from environment variables.


Django
------
Here is an example for integrating this with Django, using Vault to get
database credentials. When using PostgreSQL you will also want to look at
`django-postgresql-setrole <https://github.com/jdelic/django-postgresql-setrole>`__.

.. code-block:: python

    # in settings.py
    VAULT = VaultAuth12Factor.fromenv()
    CREDS = VaultCredentialProvider("https://vault.local:8200/", VAULT,
                                    os.getenv("VAULT_DATABASE_PATH",
                                    "db-mydatabase/creds/fullaccess"),
                                    os.getenv("VAULT_CA", None), True,
                                    DEBUG)

    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.postgresql',
            'NAME': os.getenv("DATABASE_NAME", "mydatabase"),
            'USER': CREDS.username,
            'PASSWORD': CREDS.password,
            'HOST': '127.0.0.1',
            'PORT': '5432',
            # requires django-postgresql-setrole
            'SET_ROLE': os.getenv("DATABASE_PARENTROLE", "mydatabaseowner")
        }
    }

