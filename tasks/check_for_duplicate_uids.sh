#!/bin/bash

cut -f3 -d":" /etc/passwd | sort -n | uniq -d | while read -r uid; do
  users=$(awk -F: -v n="$uid" '($3 == n) { print $1 }' /etc/passwd | xargs)
  echo "Duplicate UID ($uid): $users"
done

exit 0
