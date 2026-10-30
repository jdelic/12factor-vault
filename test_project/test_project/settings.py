"""
Settings for the integration tests. The database configuration mirrors how authserver connects to PostgreSQL
through Vault: AppRole authentication configured from the environment, credentials from Vault's database secrets
engine and SET ROLE to the role that owns the database.
"""
import os

from vault12factor import VaultCredentialProvider, VaultAuth12Factor, DjangoAutoRefreshDBCredentialsDict


SECRET_KEY = "only-used-for-tests"
DEBUG = False
ALLOWED_HOSTS = ["testserver"]

INSTALLED_APPS = [
    "postgresql_setrole",
    "django_dbconn_retry",
    "vault12factor",
]

MIDDLEWARE = []  # type: list[str]
ROOT_URLCONF = "test_project.urls"
USE_TZ = True
TEST_RUNNER = "test_project.runner.ExistingDatabaseTestRunner"

VAULT_ADDRESS = os.getenv("VAULT_ADDR", "http://127.0.0.1:8200/")

VAULT = VaultAuth12Factor.fromenv()
CREDS = VaultCredentialProvider(VAULT_ADDRESS, VAULT,
                                os.getenv("VAULT_DATABASE_PATH", "postgresql/creds/vaulttest_fullaccess"),
                                os.getenv("VAULT_CA", None), True,
                                DEBUG)

DATABASES = {
    "default": DjangoAutoRefreshDBCredentialsDict(CREDS, {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.getenv("DATABASE_NAME", "vaulttest"),
        "USER": CREDS.username,
        "PASSWORD": CREDS.password,
        "HOST": os.getenv("DATABASE_HOST", "127.0.0.1"),
        "PORT": os.getenv("DATABASE_PORT", "5432"),
        "SET_ROLE": os.getenv("DATABASE_PARENTROLE", "vaulttest"),
    }),
}
