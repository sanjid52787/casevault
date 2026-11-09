#!/usr/bin/env sh
# Generates local Docker secret files. It never prints secret material.
set -eu
umask 077
output_dir="${1:-secrets}"
mkdir -p "$output_dir"

require_absent() { [ ! -e "$1" ] || { echo "Refusing to overwrite $1" >&2; exit 1; }; }
write_random() { require_absent "$1"; openssl rand -base64 36 > "$1"; chmod 600 "$1"; }

for name in postgres_password db_password migrator_password audit_hmac_key session_secret; do
  write_random "$output_dir/$name.txt"
done

keyset="$output_dir/tink-keyset.json"
require_absent "$keyset"
sh ./mvnw -q -DskipTests compile
sh ./mvnw -q dependency:build-classpath -Dmdep.outputFile=target/tink-classpath.txt
classpath="target/classes:$(cat target/tink-classpath.txt)"
java -cp "$classpath" uk.ac.ravensbourne.casevault.crypto.DevTinkKeysetGenerator "$keyset"
chmod 600 "$keyset"
echo "Created local Docker secrets in $output_dir. Do not commit, copy, or log these files."
