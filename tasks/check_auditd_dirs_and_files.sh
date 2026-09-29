#!/bin/bash

audit_dir="${PT_audit_dir:-/var/log/audit}"
stat -c "%n %a" "${audit_dir}" "${audit_dir}"/*

exit 0
