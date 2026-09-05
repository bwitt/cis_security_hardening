#!/bin/bash

RPCV="$(sudo -Hiu root env | grep '^PATH' | cut -d= -f2)"
echo "$RPCV" | grep -q "::" && echo "root's path contains a empty directory (::)"
echo "$RPCV" | grep -q ":$" && echo "root's path contains a trailing (:)"
for x in $(echo "$RPCV" | tr ":" " "); do
  if [ "$x" = "." ]; then
    echo "PATH contains current working directory (.)"
    continue
  fi

  if [ ! -d "$x" ]; then
    echo "$x is not a directory"
    continue
  fi

  owner=$(stat -L -c "%U" "$x")
  dirperm=$(stat -L -c "%A" "$x")

  [ "$owner" != "root" ] && echo "$x is not owned by root"
  [ "$(echo "$dirperm" | cut -c6)" != "-" ] && echo "$x is group writable"
  [ "$(echo "$dirperm" | cut -c9)" != "-" ] && echo "$x is world writable"
done

exit 0
