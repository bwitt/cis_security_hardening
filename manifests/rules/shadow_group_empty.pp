# @summary
#    Ensure shadow group is empty
#
# The shadow group allows system programs which require access the ability to read the
# /etc/shadow file. No users should be assigned to the shadow group.
#
# Rationale:
# Any users assigned to the shadow group would be granted read access to the /etc/shadow file.
# If attackers can gain read access to the /etc/shadow file, they can easily run a password
# cracking program against the hashed passwords to break them.
#
# Note: this does not reassign the primary group of any user whose primary group is the shadow
# group -- picking a replacement primary group is site-specific and must be done manually.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::shadow_group_empty':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::shadow_group_empty (
  Boolean $enforce = false,
) {
  if $enforce {
    exec { 'remove all members from the shadow group':
      command => 'sed -ri \'s/(^shadow:[^:]*:[^:]*:)([^:]+$)/\1/\' /etc/group',
      path    => ['/bin', '/usr/bin'],
      onlyif  => 'test -n "$(awk -F: \'($1=="shadow") {print $NF}\' /etc/group)"',
    }
  }
}
