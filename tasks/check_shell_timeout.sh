#!/bin/bash

output1=""
output2=""

# Ceiling comes from the tmout task parameter (defaults to the CIS-mandated
# 900s). This used to be two hand-built digit-range regexes that disagreed
# with each other: the "compliant" check spliced in ${PT_tmout} as a literal
# accepted value while the "invalid" check had 700-999 hardcoded, so any
# configured value in 700-900 (e.g. the module's own 900s default) matched
# both the compliant AND the invalid pattern at once. Extracting the actual
# value and comparing it numerically against the same ceiling avoids
# re-deriving a bespoke digit-range regex per ceiling.
# shellcheck disable=SC2154
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
