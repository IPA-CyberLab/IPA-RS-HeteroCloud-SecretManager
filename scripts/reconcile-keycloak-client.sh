#!/usr/bin/env bash
# Run as root on a host with the existing HeteroCloud Keycloak installation.
set -euo pipefail
umask 077

origin=${HETEROSECRETS_PUBLIC_ORIGIN:?OpenBao UI origin is required}
legacy_origin=${HETEROSECRETS_LEGACY_ORIGIN:-}
issuer=${HETEROSECRETS_OIDC_ISSUER:?Keycloak realm issuer is required}
owner_email=${HETEROSECRETS_OWNER_EMAIL:?Exact owner email is required}
client_id=${HETEROSECRETS_CLIENT_ID:-heterosecretmanager-web}
password_file=${HETEROSECRETS_KEYCLOAK_ADMIN_PASSWORD_FILE:-/etc/heteronetwork/keycloak/bootstrap-admin.password}
kcadm=${HETEROSECRETS_KCADM:-/opt/heteronetwork/keycloak/bin/kcadm.sh}
server=${HETEROSECRETS_KEYCLOAK_SERVER:-http://127.0.0.1:18080}
secret_file=${HETEROSECRETS_CLIENT_SECRET_FILE:-/etc/heteronetwork/keycloak/heterosecretmanager-client.secret}

[[ $EUID == 0 && ( $origin =~ ^https://[^/]+$ || $origin =~ ^http://[a-z0-9.-]+\.heteronetwork\.internal:[0-9]+$ ) && $issuer =~ ^https://[^/]+/id/realms/[A-Za-z0-9._-]+$ ]] || exit 2
[[ -z $legacy_origin || $legacy_origin =~ ^https://[^/]+$ ]] || exit 2
[[ $client_id =~ ^[A-Za-z0-9._-]+$ && $owner_email =~ ^[^[:space:]@]+@[^[:space:]@]+$ ]] || exit 2
[[ -x $kcadm && -f $password_file && ! -L $password_file ]] || exit 2
command -v jq >/dev/null
command -v openssl >/dev/null

realm=${issuer##*/}
work_dir=$(mktemp -d /run/heterosecrets-keycloak.XXXXXX)
trap 'rm -rf "$work_dir"' EXIT
config=$work_dir/kcadm.config
admin_password=$(tr -d '\r\n' <"$password_file")
KC_CLI_PASSWORD="$admin_password" "$kcadm" config credentials --config "$config" \
  --server "$server" --realm master --user admin </dev/null >/dev/null
unset admin_password

"$kcadm" get users --config "$config" -r "$realm" \
  -q "email=$owner_email" >"$work_dir/users.json"
owner_subject=$(jq -er --arg email "$owner_email" \
  '[.[] | select(.email == $email and .enabled == true)] | if length == 1 then .[0].id else error("owner missing or ambiguous") end' \
  "$work_dir/users.json")

install -d -o root -g root -m 0700 "$(dirname "$secret_file")"
if [[ -e $secret_file ]]; then
  [[ -f $secret_file && ! -L $secret_file ]] || exit 2
else
  openssl rand -hex 32 >"$secret_file"
fi
chmod 0600 "$secret_file"
chown root:root "$secret_file"

"$kcadm" get clients --config "$config" -r "$realm" \
  -q "clientId=$client_id" >"$work_dir/clients.json"
count=$(jq 'length' "$work_dir/clients.json")
[[ $count == 0 || $count == 1 ]] || exit 2
uuid=''
if [[ $count == 1 ]]; then
  uuid=$(jq -er '.[0].id' "$work_dir/clients.json")
  "$kcadm" get "clients/$uuid/client-secret" --config "$config" -r "$realm" \
    | jq -jer '.value' >"$secret_file"
  [[ $(wc -c <"$secret_file") -ge 32 ]] || exit 2
fi

jq -n --arg id "$client_id" --arg origin "$origin" --arg legacy "$legacy_origin" \
  --rawfile secret "$secret_file" '{
    clientId: $id,
    name: "Hetero Secret Manager",
    enabled: true,
    protocol: "openid-connect",
    publicClient: false,
    bearerOnly: false,
    consentRequired: false,
    standardFlowEnabled: true,
    implicitFlowEnabled: false,
    directAccessGrantsEnabled: false,
    serviceAccountsEnabled: false,
    clientAuthenticatorType: "client-secret",
    secret: ($secret | rtrimstr("\n")),
    rootUrl: $origin,
    baseUrl: ($origin + "/ui/"),
    redirectUris: ([
      ($origin + "/v1/auth/oidc/callback"),
      ($origin + "/ui/vault/auth/oidc/oidc/callback"),
      "http://localhost:8250/oidc/callback"
    ] + (if $legacy == "" then [] else [
      ($legacy + "/v1/auth/oidc/callback"),
      ($legacy + "/ui/vault/auth/oidc/oidc/callback")
    ] end)),
    webOrigins: ([$origin] + (if $legacy == "" then [] else [$legacy] end)),
    attributes: {
      "pkce.code.challenge.method": "S256",
      "post.logout.redirect.uris": ($origin + "/*"),
      "oauth2.device.authorization.grant.enabled": "false"
    }
  }' >"$work_dir/client.json"
if [[ -n $uuid ]]; then
  "$kcadm" update "clients/$uuid" --config "$config" -r "$realm" \
    -f "$work_dir/client.json" >/dev/null
else
  "$kcadm" create clients --config "$config" -r "$realm" \
    -f "$work_dir/client.json" >/dev/null
fi

# This JSON must be consumed in process memory, never written to a shared file.
jq -n --arg client_id "$client_id" --arg issuer "$issuer" \
  --arg owner_subject "$owner_subject" --rawfile client_secret "$secret_file" \
  '{client_id: $client_id, client_secret: ($client_secret | rtrimstr("\n")),
    issuer: $issuer, owner_subject: $owner_subject}'
