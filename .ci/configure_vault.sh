#!/bin/bash
# Configures a Vault server to hand out PostgreSQL credentials for the test project through AppRole
# authentication, similar to how authserver is set up in production.
#
# Requires VAULT_ADDR and VAULT_ROOT_TOKEN. DATABASE_HOST and DATABASE_PORT default to 127.0.0.1:5432.
# Writes VAULT_ROLEID and VAULT_SECRETID to $GITHUB_ENV when running on GitHub Actions and prints them as
# export statements otherwise, so you can run: eval "$(.ci/configure_vault.sh)"

set -euo pipefail

# keep stdout for the export statements, so the output can be used with eval
exec 3>&1 1>&2

: "${VAULT_ADDR:?VAULT_ADDR must be set}"
: "${VAULT_ROOT_TOKEN:?VAULT_ROOT_TOKEN must be set}"
export VAULT_TOKEN="$VAULT_ROOT_TOKEN"
DATABASE="${DATABASE_HOST:-127.0.0.1}:${DATABASE_PORT:-5432}"

vault secrets enable -path=postgresql database

vault write postgresql/config/vaulttest \
    plugin_name=postgresql-database-plugin \
    allowed_roles="vaulttest_fullaccess" \
    connection_url="postgresql://{{username}}:{{password}}@${DATABASE}/vaulttest?sslmode=disable" \
    username="vaultadmin" \
    password="vaultadmin"

vault write postgresql/roles/vaulttest_fullaccess \
    db_name=vaulttest \
    default_ttl=10m \
    max_ttl=1h \
    creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN ENCRYPTED PASSWORD '{{password}}' \
        VALID UNTIL '{{expiration}}' IN ROLE vaulttest INHERIT NOCREATEROLE NOCREATEDB NOSUPERUSER \
        NOREPLICATION NOBYPASSRLS;" \
    revocation_statements="DROP ROLE \"{{name}}\";"

echo 'path "postgresql/creds/vaulttest_fullaccess" {
    capabilities = ["read"]
}' | vault policy write vaulttest_fullaccess -

vault auth enable approle
vault write auth/approle/role/vaulttest \
    policies=vaulttest_fullaccess \
    secret_id_num_uses=0 \
    secret_id_ttl=0 \
    period=24h \
    token_ttl=0 \
    token_max_ttl=0

ROLE_ID="$(vault read -field=role_id auth/approle/role/vaulttest/role-id)"
SECRET_ID="$(vault write -f -field=secret_id auth/approle/role/vaulttest/secret-id)"

if [ -n "${GITHUB_ENV:-}" ]; then
    # workflow commands must go to stdout
    echo "::add-mask::$SECRET_ID" >&3
    echo "VAULT_ROLEID=$ROLE_ID" >> "$GITHUB_ENV"
    echo "VAULT_SECRETID=$SECRET_ID" >> "$GITHUB_ENV"
else
    echo "export VAULT_ROLEID=$ROLE_ID" >&3
    echo "export VAULT_SECRETID=$SECRET_ID" >&3
fi
