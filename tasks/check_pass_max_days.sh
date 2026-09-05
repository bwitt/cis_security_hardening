#!/bin/bash

pmax=$(awk '$1 == "PASS_MAX_DAYS" { print $2 }' /etc/login.defs | head -1)
if [ -z "$pmax" ]; then
  echo "PASS_MAX_DAYS is not set in /etc/login.defs"
  exit 0
fi

echo "PASS_MAX_DAYS = ${pmax}"
awk -F : -v P="$pmax" '(/^[^:]+:[^!*]/ && $5 > P){print $1 " " $5}' /etc/shadow

exit 0
