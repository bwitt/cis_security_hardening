#!/bin/bash

uid_min=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
if [ -z "$uid_min" ]; then
  echo "UID_MIN is not set in /etc/login.defs"
  exit 0
fi

awk -F: -v m="$uid_min" '$1!~/(root|sync|shutdown|halt|^\+)/ && $3<m && $7!~/((\/usr)?\/sbin\/nologin)/ && $7!~/(\/bin)?\/false/ {print}' /etc/passwd
awk -F: -v m="$uid_min" '($1!~/(root|^\+)/ && $3<m) {print $1}' /etc/passwd | xargs -I '{}' passwd -S '{}' | awk '($2!~/LK?/) {print $1}'

exit 0
