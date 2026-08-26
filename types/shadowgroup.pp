# @summary
#    A group owner permitted by CIS for the shadow-family files.
#
# The benchmark allows "Gid 0/root or {GID}/shadow" and nothing else.
#
# Note that root and shadow are not interchangeable in practice: setting root
# removes access for setgid-shadow helpers such as unix_chkpwd, which non-root
# PAM uses to read /etc/shadow.
type Cis_security_hardening::Shadowgroup = Enum['root', 'shadow']
