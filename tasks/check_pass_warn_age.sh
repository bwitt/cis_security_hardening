#!/bin/bash

pwrn=$(awk '$1 == "PASS_WARN_AGE" { print $2 }' /etc/login.defs | head -1)
if [ -z "$pwrn" ]; then
  echo "PASS_WARN_AGE is not set in /etc/login.defs"
  exit 0
fi

echo "PASS_WARN_AGE = ${pwrn}"
awk -F : -v P="$pwrn" '(/^[^:]+:[^!*]/ && $6 < P){print $1 " " $6}' /etc/shadow

exit 0
