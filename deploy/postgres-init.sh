#!/bin/sh
set -eu
app_password="$(cat /run/secrets/app_db_password)"
case "$app_password" in
  ''|*[!A-Za-z0-9_-]*) echo 'Application database password must be a nonempty URL-safe token' >&2; exit 1 ;;
esac
psql --username="$POSTGRES_USER" --dbname="$POSTGRES_DB" --set=ON_ERROR_STOP=1 <<SQL
CREATE ROLE agentsec LOGIN PASSWORD '$app_password' NOSUPERUSER NOCREATEDB NOCREATEROLE;
ALTER DATABASE agentsec OWNER TO agentsec;
ALTER SCHEMA public OWNER TO agentsec;
GRANT CONNECT ON DATABASE agentsec TO agentsec;
GRANT USAGE, CREATE ON SCHEMA public TO agentsec;
SQL
