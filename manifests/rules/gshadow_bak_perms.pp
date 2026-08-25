# @summary
#    Ensure permissions on /etc/gshadow- are configured
#
# The /etc/gshadow- file is used to store backup information about groups that is critical
# to the security of those accounts, such as the hashed password and other security information.
#
# Rationale:
# It is critical to ensure that the /etc/gshadow- file is protected from unauthorized access.
# Although it is protected by default, the file permissions could be changed either inadvertently
# or through malicious actions.
#
# @param enforce
#    Enforce the rule
#
# @param mode
#    File mode to enforce. Falls back to the per-OS default when undef.
#    The benchmark asks for 0640 or more restrictive.
#
# @param group
#    Group owner to enforce. The benchmark allows either root or shadow.
#
# @example
#   class { 'cis_security_hardening::rules::gshadow_bak_perms':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::gshadow_bak_perms (
  Boolean                                       $enforce = false,
  Optional[Cis_security_hardening::Shadowmode]  $mode    = undef,
  Cis_security_hardening::Shadowgroup           $group   = 'root',
) {
  if $enforce {
    if $facts['os']['name'].downcase() == 'debian' {
      $default_mode = '0640'
    } else {
      $default_mode = '0000'
    }

    file { '/etc/gshadow-':
      ensure => file,
      owner  => 'root',
      group  => $group,
      mode   => pick($mode, $default_mode),
    }
  }
}
