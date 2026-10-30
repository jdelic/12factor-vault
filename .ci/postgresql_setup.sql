-- Owner of the test database. The users that Vault creates are members of this role and switch to it using
-- django-postgresql-setrole's SET ROLE, so they never own any objects themselves and can be dropped when their
-- lease is revoked.
CREATE ROLE vaulttest NOLOGIN;
CREATE DATABASE vaulttest OWNER vaulttest;

-- The user that Vault uses to create and drop the users it hands out. It needs ADMIN OPTION on vaulttest to
-- create roles IN ROLE vaulttest.
CREATE ROLE vaultadmin WITH LOGIN CREATEROLE PASSWORD 'vaultadmin';
GRANT vaulttest TO vaultadmin WITH ADMIN OPTION;
