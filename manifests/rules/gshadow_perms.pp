# @summary
#    Ensure permissions on /etc/gshadow are configured
#
# The /etc/gshadow file is used to store the information about groups that is critical to
# the security of those accounts, such as the hashed password and other security information.
#
# Rationale:
# If attackers can gain read access to the /etc/gshadow file, they can easily run a password cracking
# program against the hashed password to break it. Other security information that is stored in the
# /etc/gshadow file (such as group administrators) could also be useful to subvert the group.
#
# @param enforce
#    Enforce the rule
#
# @param mode
#    File mode to enforce. The benchmark asks for 0640 or more restrictive.
#
# @param group
#    Group owner to enforce. The benchmark allows either root or shadow.
#
# @example
#   class { 'cis_security_hardening::rules::gshadow_perms':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::gshadow_perms (
  Boolean                             $enforce = false,
  Cis_security_hardening::Shadowmode  $mode    = '0000',
  Cis_security_hardening::Shadowgroup $group   = 'root',
) {
  if $enforce {
    file { '/etc/gshadow':
      ensure => file,
      owner  => 'root',
      group  => $group,
      mode   => $mode,
    }
  }
}
