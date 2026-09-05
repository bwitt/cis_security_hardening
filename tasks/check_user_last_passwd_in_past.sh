#!/bin/bash

awk -F : '/^[^:]+:[^!*]/{print $1}' /etc/shadow | while read -r usr; do
  change=$(chage --list "$usr" 2>/dev/null | grep '^Last password change' | cut -d: -f2)

  # accounts that never had a password set have nothing to compare
  [ -z "$change" ] && continue
  echo "$change" | grep -qi 'never' && continue

  changed=$(date --date="$change" +%s 2>/dev/null) || continue
  if [ "$changed" -gt "$(date '+%s')" ]; then
    echo "user: $usr password change date:$change"
  fi
done

exit 0
