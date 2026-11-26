#!/bin/sh
# Provisions a throwaway Warpgate (container webssh-warpgate) for the gateway
# lab test: target "modern" (ssh-modern of the shared lab, user pwuser),
# user alice (public key + TOTP) and bob (password + TOTP), all synthetic.
# Writes the generated secrets to $1 (mode 0700), which the test reads.
set -eu
dir=${1:?usage: warpgate-provision.sh <state dir>}
lab=${WEBSSH_LAB_RUNTIME:-$(cd "$(dirname "$0")/../../../../tests/lab/runtime" && pwd)}
base=https://localhost:18888
umask 077
jar="$dir/jar"
api() { curl -sSfk -b "$jar" -c "$jar" -H 'Content-Type: application/json' "$@"; }
api -o /dev/null -d "$(jq -n --arg p "$(cat "$dir/admin")" '{username:"admin",password:$p}')" "$base/@warpgate/api/auth/login"
adm="$base/@warpgate/admin/api"
role=$(api -d '{"name":"webssh-test"}' "$adm/roles" | jq -r .id)
target=$(api -d "$(jq -n --arg p "$(cat "$lab/secrets/ssh-pwuser")" '{name:"modern",options:{kind:"Ssh",host:"ssh-modern.lab.test",port:22,username:"pwuser",allow_insecure_algos:false,auth:{kind:"Password",password:$p}},ticket_requests_disabled:true,ticket_require_approval:false,require_approval:false}')" "$adm/targets" | jq -r .id)
api -o /dev/null -X POST "$adm/targets/$target/roles/$role"
head -c 20 /dev/urandom > "$dir/otp.bin"
od -An -tx1 "$dir/otp.bin" | tr -d ' \n' > "$dir/otp.hex"
otp_bytes=$(od -An -tu1 "$dir/otp.bin" | tr -s ' \n' ' ' | jq -Rc 'split(" ")|map(select(.!=""))|map(tonumber)')
rm -f "$dir/otp.bin"
head -c 18 /dev/urandom | base64 | tr -d '/+=' > "$dir/bob.password"
for u in alice bob; do
	id=$(api -d "{\"username\":\"$u\"}" "$adm/users" | jq -r .id)
	api -o /dev/null -X POST -d '{}' "$adm/users/$id/roles/$role"
	api -o /dev/null -d "{\"secret_key\":$otp_bytes}" "$adm/users/$id/credentials/otp"
	if [ "$u" = alice ]; then
		api -o /dev/null -d "$(jq -n --arg k "$(cat "$lab/ssh/client/ed25519.pub")" '{label:"webssh-test",openssh_public_key:$k}')" "$adm/users/$id/credentials/public-keys"
		policy='["PublicKey","Totp"]'
	else
		api -o /dev/null -d "$(jq -n --arg p "$(cat "$dir/bob.password")" '{password:$p}')" "$adm/users/$id/credentials/passwords"
		policy='["Password","Totp"]'
	fi
	api -o /dev/null -X PUT -d "{\"username\":\"$u\",\"credential_policy\":{\"ssh\":$policy}}" "$adm/users/$id"
done
echo "provisioned role=$role target=$target"
