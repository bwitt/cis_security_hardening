#!/bin/bash

awk -F : -v P="${PT_inactive:-30}" '(/^[^:]+:[^!*]/ && ($7 ~ /^[[:space:]]*$/ || $7 > P)){print $1 " " $7}' /etc/shadow

exit 0
