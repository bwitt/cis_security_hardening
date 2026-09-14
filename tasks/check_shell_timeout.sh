#!/bin/bash

output1=""
output2=""

max_tmout="${PT_tmout:-900}"

[ -f /etc/bash.bashrc ] && BRC="/etc/bash.bashrc"
for f in "$BRC" /etc/profile /etc/profile.d/*.sh; do
  [ -f "$f" ] || continue

  tmout_value=$(grep -Po '\bTMOUT=\K[0-9]+' "$f" | tail -1)
  [ -z "$tmout_value" ] && continue

  if [ "$tmout_value" -ge 1 ] && [ "$tmout_value" -le "$max_tmout" ] &&
    grep -Pq "\breadonly\h+TMOUT(\h+|\h*;|\h*$|=${tmout_value})\b" "$f" &&
    grep -Pq '\bexport\h+([^#\n\r]+\h+)?TMOUT\b' "$f"; then
    output1="$f"
  fi

  if [ "$tmout_value" -lt 1 ] || [ "$tmout_value" -gt "$max_tmout" ]; then
    output2="$f:TMOUT=$tmout_value"
  fi
done

if [ -n "$output1" ] && [ -z "$output2" ]; then
  echo -e "\nPASSED\n\nTMOUT is configured in: \"$output1\"\n"
else
  [ -z "$output1" ] && echo -e "\nFAILED\n\nTMOUT is not configured\n"
  [ -n "$output2" ] && echo -e "\nFAILED\n\nTMOUT is incorrectly configured in: \"$output2\"\n"
fi

exit 0
