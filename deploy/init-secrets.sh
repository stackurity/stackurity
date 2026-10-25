#!/bin/sh
# Generates the database password and connection URL used by docker-compose.yml.
set -eu
cd "$(dirname "$0")"
mkdir -p secrets
chmod 700 secrets
if [ ! -s secrets/db_password ]; then
  head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > secrets/db_password
  echo "generated secrets/db_password"
fi
printf 'postgres://stackurity:%s@postgres:5432/stackurity?sslmode=disable' "$(cat secrets/db_password)" > secrets/database_url
# The containers run as non-root users, so the files must be readable inside
# them; the 0700 directory keeps them private on the host.
chmod 644 secrets/db_password secrets/database_url
echo "wrote secrets/database_url"
