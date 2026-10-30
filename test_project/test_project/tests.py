import os
from typing import Any, Dict

import hvac
from django.conf import settings
from django.db import connection
from django.test import SimpleTestCase
from django_dbconn_retry import pre_reconnect


class VaultDatabaseConnectionTests(SimpleTestCase):
    databases = {"default"}

    def setUp(self) -> None:
        # start every test with a new database connection, like every request does with CONN_MAX_AGE=0
        connection.close()

    def whoami(self) -> Dict[str, Any]:
        response = self.client.get("/whoami/")
        self.assertEqual(response.status_code, 200)
        return response.json()

    def role_exists(self, rolename: str) -> bool:
        with connection.cursor() as cursor:
            cursor.execute("SELECT count(*) FROM pg_roles WHERE rolname = %s", (rolename,))
            return cursor.fetchone()[0] == 1

    def test_connects_with_vault_credentials(self) -> None:
        result = self.whoami()
        self.assertTrue(result["session_user"].startswith("v-approle-"), result["session_user"])
        self.assertEqual(result["session_user"], settings.CREDS.username)
        # django-postgresql-setrole switched to the role that owns the database
        self.assertEqual(result["current_user"], "vaulttest")

    def test_reconnects_with_new_credentials_after_lease_expired(self) -> None:
        old_user = self.whoami()["session_user"]
        connection.close()

        # Simulate the lease running out: Vault revokes it, which drops the PostgreSQL user, and the provider's
        # cached lease is marked as expired.
        root = hvac.Client(url=settings.VAULT_ADDRESS, token=os.environ["VAULT_ROOT_TOKEN"])
        root.sys.revoke_lease(settings.CREDS._lease_id)
        settings.CREDS._updatetime = settings.CREDS._now()

        new_user = self.whoami()["session_user"]
        self.assertNotEqual(new_user, old_user)
        self.assertEqual(new_user, settings.CREDS.username)
        self.assertFalse(self.role_exists(old_user))

    def test_connects_without_retry_after_lease_expired(self) -> None:
        old_user = self.whoami()["session_user"]
        connection.close()

        root = hvac.Client(url=settings.VAULT_ADDRESS, token=os.environ["VAULT_ROOT_TOKEN"])
        root.sys.revoke_lease(settings.CREDS._lease_id)
        settings.CREDS._updatetime = settings.CREDS._now()

        # django-dbconn-retry only sends pre_reconnect after a connection attempt failed
        failed_attempts = []

        def count_failed_attempts(sender: type, **kwargs: Any) -> None:
            failed_attempts.append(sender)

        pre_reconnect.connect(count_failed_attempts)
        try:
            new_user = self.whoami()["session_user"]
        finally:
            pre_reconnect.disconnect(count_failed_attempts)

        self.assertNotEqual(new_user, old_user)
        self.assertEqual(failed_attempts, [])
