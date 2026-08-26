# @summary
#    A file mode permitted by CIS for the shadow-family files.
#
# The benchmark asks for "640 or more restrictive", so the owner may have at
# most read and write, the group at most read, and other nothing at all.
#
# Permits 0000, 0200, 0400, 0440, 0600, 0640 and the other combinations that
# set no bit outside 0640. Rejects anything looser, e.g. 0644 (other can read),
# 0660 (group can write) or 0740 (owner can execute).
type Cis_security_hardening::Shadowmode = Pattern[/\A0[0246][04]0\z/]
