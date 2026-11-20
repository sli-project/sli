"""Inspect optional local PostgreSQL storage without Docker or a database."""
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


class OptionalPostgresLayoutTests(unittest.TestCase):
    def setUp(self):
        self.compose = yaml.safe_load((ROOT / "deploy/docker-compose.yml").read_text())
        self.postgres = self.compose["services"]["postgres"]

    def test_pgdata_uses_existing_named_volume_root(self):
        # Retain the established location; changing to a versioned layout needs
        # an explicit migration rather than an implicit configuration change.
        self.assertEqual(self.postgres["environment"].get("PGDATA"), "/var/lib/postgresql/data")
        self.assertEqual(self.postgres["volumes"], ["sli-postgres-data:/var/lib/postgresql/data"])
        self.assertEqual(self.compose["volumes"]["sli-postgres-data"], {"name": "sli-postgres-data"})

    def test_database_remains_optional_and_loopback_only(self):
        self.assertEqual(self.postgres["image"], "postgres:18")
        self.assertEqual(self.postgres["profiles"], ["optional-docker-pg"])
        self.assertEqual(self.postgres["ports"], ["127.0.0.1:55433:5432"])
        self.assertNotIn("entrypoint", self.postgres)
        self.assertNotIn("command", self.postgres)

    def test_production_keeps_parent_mount_and_versioned_default(self):
        compose = yaml.safe_load((ROOT / "deploy/linux/docker-compose.yml").read_text())
        postgres = compose["services"]["postgres"]
        self.assertIn("postgres-data:/var/lib/postgresql", postgres["volumes"])
        self.assertNotIn("PGDATA", postgres["environment"])


if __name__ == "__main__":
    unittest.main()
