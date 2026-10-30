from typing import Any

from django.test.runner import DiscoverRunner


class ExistingDatabaseTestRunner(DiscoverRunner):
    """
    Runs the tests against the configured database instead of creating a test database. The users that Vault
    hands out can't create databases, and the tests only need to check that connecting through Vault works.
    """
    def setup_databases(self, **kwargs: Any) -> None:
        return None

    def teardown_databases(self, old_config: Any, **kwargs: Any) -> None:
        pass
