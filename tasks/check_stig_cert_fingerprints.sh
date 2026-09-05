#!/bin/bash

# SHA256 fingerprints of the approved DoD certificates
dod_fingerprints="
9676F287356C89A12683D65234098CB77C4F1C18F23C0E541DE0E196725B7EBE
B107B33F453E5510F68E513110C6F6944BACC263DF0137F821C1B3C2F8F863D2
559A5189452B13F8233F0022363C06F26E3C517C1D4B77445035959DF3244F74
1F4EDE9DC2A241F6521BF518424ACD49EBE84420E69DAF5BAC57AF1F8EE294A9
"

for f in /etc/ssl/certs/*; do
  [ -f "$f" ] || continue

  fingerprint=$(openssl x509 -sha256 -in "$f" -noout -fingerprint 2>/dev/null | cut -d= -f2 | tr -d ':')
  [ -z "$fingerprint" ] && continue

  if ! echo "$dod_fingerprints" | grep -qxF "$fingerprint"; then
    echo "$f $fingerprint"
  fi
done

exit 0
