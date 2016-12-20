# -* encoding: utf-8 *-
import datetime
import logging
import os
from typing import Dict, Tuple, Union, Any, TypeVar, Type

import hvac
import pytz
from django.apps.config import AppConfig
from requests.exceptions import RequestException
from django.db.backends.base import base as django_db_base

_log = logging.getLogger(__name__)
default_app_config = 'vault12factor.DjangoVaultDatabaseIntegration'


class VaultCredentialProviderException(Exception):
    pass


class VaultAuthentication:
    """
    The basic interface expected by `VaultCredentialProvider`. Most implementations will want to go
    with `BaseVaultAuthenticator`.
    """
    def authenticated_client(self, *args: Any, **kwargs: Any) -> hvac.Client:
        """
        :param args: must be passed on to `hvac.Client`
        :param kwargs: must be passed on to `hvac.Client`
        :return: A `hvac.Client` instance which is authenticated with Vault
        """
        raise NotImplementedError("Subclasses of VaultAuthentication must implement authenticated_client")


# This won't work until https://github.com/python/mypy/issues/1212 is fixed
T = TypeVar('T', bound='BaseVaultAuthenticator')


class BaseVaultAuthenticator(VaultAuthentication):
    """
    Use one of the factory methods (`app_id`, `token`, `ssl_client_cert`) to create an instance.
    """
    def __init__(self) -> None:
        self.credentials = None  # type: Union[str, Tuple[str, str]]
        self.authtype = None  # type: str
        self.unwrap_response = False
        super().__init__()

    @classmethod
    def app_id(cls: Type[T], app_id: str, user_id: str) -> T:
        i = cls()
        i.credentials = (app_id, user_id)
        i.authtype = "app-id"
        return i

    @classmethod
    def ssl_client_cert(cls: Type[T], certfile: str, keyfile: str) -> T:
        if not os.path.isfile(certfile) or not os.access(certfile, os.R_OK):
            raise VaultCredentialProviderException("File not found or not readable: %s" % certfile)

        if not os.path.isfile(keyfile) or not os.access(keyfile, os.R_OK):
            raise VaultCredentialProviderException("File not found or not readable: %s" % keyfile)

        i = cls()
        i.credentials = (certfile, keyfile)
        i.authtype = "ssl"
        return i

    @classmethod
    def token(cls: Type[T], token: str) -> T:
        i = cls()
        i.credentials = token
        i.authtype = "token"
        return i

    def authenticated_client(self, *args: Any, **kwargs: Any) -> hvac.Client:
        if self.authtype == "token":
            cl = hvac.Client(token=self.credentials, *args, **kwargs)
        elif self.authtype == "app-id":
            cl = hvac.Client(*args, **kwargs)
            cl.auth_app_id(*self.credentials)
        elif self.authtype == "ssl":
            cl = hvac.Client(cert=self.credentials, *args, **kwargs)
            cl.auth_tls()
        else:
            raise VaultCredentialProviderException("no auth config")

        if not cl.is_authenticated():
            raise VaultCredentialProviderException("Unable to authenticate Vault client using provided credentials "
                                                   "(type=%s)" % self.authtype)
        return cl


class VaultAuth12Factor(BaseVaultAuthenticator):
    """
    This class configures a Vault client instance from environment variables. The environment variables supported are:

    ===========================  =========================  ==================================
    Environment Variable         Vault auth backend         Direct configuration static method
    ===========================  =========================  ==================================
    VAULT_TOKEN                  Token authentication       token(str)
    VAULT_APPID, VAULT_USERID    App-id authenticaion       app_id(str, str)
    VAULT_SSLCERT, VAULT_SSLKEY  SSL Client authentication  ssl_client_cert(str, str)
    ===========================  =========================  ==================================

    It can also be configured directly by calling one of the direct configuration methods.
    """
    def __init__(self) -> None:
        super().__init__()

    @staticmethod
    def has_envconfig() -> bool:
        """
        (static)
        :return: True if enough information is available in the environment to authenticate to Vault
        """
        if (os.getenv("VAULT_TOKEN", None) or
                (os.getenv("VAULT_APPID", None) and os.getenv("VAULT_USERID", None)) or
                (os.getenv("VAULT_SSLCERT", None) and os.getenv("VAULT_SSLKEY", None))):
            return True

        return False

    @staticmethod
    def fromenv() -> 'VaultAuth12Factor':
        """
        :return: Load configuration from the environment and return a configured instance
        """
        i = None  # type: VaultAuth12Factor
        if os.getenv("VAULT_TOKEN", None):
            i = VaultAuth12Factor.token(os.getenv("VAULT_TOKEN"))
        elif os.getenv("VAULT_APPID", None) and os.getenv("VAULT_USERID", None):
            i = VaultAuth12Factor.app_id(os.getenv("VAULT_APPID"), os.getenv("VAULT_USERID"))
        elif os.getenv("VAULT_SSLCERT", None) and os.getenv("VAULT_SSLKEY", None):
            i = VaultAuth12Factor.ssl_client_cert(os.getenv("VAULT_SSLCERT"), os.getenv("VAULT_SSLKEY"))

        if i:
            e = os.getenv("VAULT_UNWRAP", "False")
            if e.lower() in ["true", "1", "yes"]:
                i.unwrap_response = True
            return i

        raise VaultCredentialProviderException("Unable to configure Vault authentication from the environment")


class VaultCredentialProvider:
    """
    The `VaultCredentialProvider` uses credentials from a `VaultAuthentication` implementation to connect to
    Vault and read credentials from `secretpath`. It then provides `username` and `password` as properties while
    managing the lease and renewing the credentials as needed.

    This class also optionally enforces connection security through `pin_cacert`.

    You can use this in a Django `settings.DATABASES` `dict` like this:

    .. code-block:: python

        VAULT = VaultAuth12Factor.fromenv()
        CREDS = VaultCredentialProvider("https://vault.local:8200/", VAULT,
                                        os.getenv("VAULT_DATABASE_PATH", "db-mydatabase/creds/fullaccess"),
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
                'SET_ROLE': os.getenv("DATABASE_PARENTROLE", "mydatabaseowner")  # requires django-postgresql-setrole
            }),
        }
    """
    def __init__(self, vaulturl: str, vaultauth: VaultAuthentication, secretpath: str, pin_cacert: str=None,
                 ssl_verify: bool=False, debug_output: bool=False) -> None:
        self.vaulturl = vaulturl
        self._vaultauth = vaultauth
        self.secretpath = secretpath
        self.pin_cacert = pin_cacert
        self.ssl_verify = ssl_verify
        self.debug_output = debug_output
        self._cache = None  # type: Dict[str, str]
        self._leasetime = None  # type: datetime.datetime
        self._updatetime = None  # type: datetime.datetime
        self._lease_id = None  # type: str

    def _now(self) -> datetime.datetime:
        return datetime.datetime.now(pytz.timezone("UTC"))

    def _refresh(self) -> None:
        vcl = self._vaultauth.authenticated_client(
            url=self.vaulturl,
            verify=self.pin_cacert if self.pin_cacert else self.ssl_verify
        )

        try:
            result = vcl.read(self.secretpath)
        except RequestException as e:
            raise VaultCredentialProviderException(
                "Unable to read credentials from path '%s' with request error: %s" %
                (self.secretpath, str(e))
            ) from e

        if "data" not in result or "username" not in result["data"] or "password" not in result["data"]:
            raise VaultCredentialProviderException(
                "Read dict from Vault path %s did not match expected structure (data->{username, password}): %s" %
                (self.secretpath, str(result))
            )

        self._cache = result["data"]
        self._lease_id = result["lease_id"]
        self._leasetime = self._now()
        self._updatetime = self._leasetime + datetime.timedelta(seconds=int(result["lease_duration"]))

        _log.debug("Loaded new Vault DB credentials from %s:\nlease_id=%s\nleasetime=%s\nduration=%s\n"
                   "username=%s\npassword=%s",
                   self.secretpath,
                   self._lease_id, str(self._leasetime), result["lease_duration"], self._cache["username"],
                   self._cache["password"] if self.debug_output else "Password withheld, debug output is disabled")

    def _get_or_update(self, key: str) -> str:
        if self._cache is None or (self._updatetime - self._now()).total_seconds() < 10:
            # if we have less than 10 seconds in a lease ot no lease at all, we get new credentials
            _log.info("Vault DB credential lease has expired, refreshing for %s" % key)
            self._refresh()
            _log.info("refresh done (%s, %s)" % (self._lease_id, str(self._updatetime)))

        return self._cache[key]

    @property
    def username(self) -> str:
        return self._get_or_update("username")

    @property
    def password(self) -> str:
        return self._get_or_update("password")


_operror_types = ()  # type: Union[Tuple[type], Tuple]
try:
    import psycopg2
except ImportError:
    pass
else:
    _operror_types += (psycopg2.OperationalError,)

try:
    import sqlite3
except ImportError:
    pass
else:
    _operror_types += (sqlite3.OperationalError,)

try:
    import MySQLdb
except ImportError:
    pass
else:
    _operror_types += (MySQLdb.OperationalError,)


def monkeypatch_django() -> None:
    def ensure_connection_with_retries(self: django_db_base.BaseDatabaseWrapper) -> None:
        if self.connection is None:
            with self.wrap_database_errors:
                try:
                    self.connect()
                except Exception as e:
                    if isinstance(e, _operror_types):
                        if hasattr(self, "_12vv_retries"):
                            if self._12vv_retries >= 1:
                                _log.debug("Retrying with new credentials from Vault didn't help %s", str(e))
                                raise
                        else:
                            _log.debug("Database connection failed. Refreshing credentials from Vault.")
                            self.settings_dict.refresh_credentials()
                            self._12vv_retries = 1
                            self.ensure_connection()
                    else:
                        _log.debug("Database connection failed, but not due to a known error for vault12factor %s",
                                   str(e))
                        raise

    django_db_base.BaseDatabaseWrapper.ensure_connection = ensure_connection_with_retries


class DjangoVaultDatabaseIntegration(AppConfig):
    name = "vault12factor"

    def ready(self) -> None:
        if VaultAuth12Factor.has_envconfig():
            from django.conf import settings
            found = False
            for k, db in settings.DATABASES.items():
                if isinstance(db, DjangoVaultDatabaseIntegration):
                    found = True

            if found:
                monkeypatch_django()


class DjangoAutoRefreshDBCredentialsDict(dict):
    def __init__(self, provider: VaultCredentialProvider, *args: Any, **kwargs: Any) -> None:
        self._provider = provider
        super().__init__(*args, **kwargs)

    def refresh_credentials(self) -> None:
        self["USER"] = self._provider.username
        self["PASSWORD"] = self._provider.password
