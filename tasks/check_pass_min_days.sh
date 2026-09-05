#!/bin/bash

pmin=$(awk '$1 == "PASS_MIN_DAYS" { print $2 }' /etc/login.defs | head -1)
if [ -z "$pmin" ]; then
  echo "PASS_MIN_DAYS is not set in /etc/login.defs"
  exit 0
fi

echo "PASS_MIN_DAYS = ${pmin}"
awk -F : -v P="$pmin" '(/^[^:]+:[^!*]/ && $4 < P){print $1 " " $4}' /etc/shadow

exit 0
