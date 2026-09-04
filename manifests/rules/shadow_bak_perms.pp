# @summary
#    Ensure permissions on /etc/shadow- are configured
#
# The /etc/shadow- file is used to store backup information about user accounts that is critical to the security
# of those accounts, such as the hashed password and other security information.
#
# Rationale:
# It is critical to ensure that the /etc/shadow- file is protected from unauthorized access. Although it is
# protected by default, the file permissions could be changed either inadvertently or through malicious actions.
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
#   class { 'cis_security_hardening::rules::shadow_bak_perms':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::shadow_bak_perms (
  Boolean                                       $enforce = false,
  Optional[Cis_security_hardening::Shadowmode]  $mode    = undef,
  Cis_security_hardening::Shadowgroup           $group   = 'root',
) {
  if $enforce {
    if $facts['os']['name'].downcase() == 'debian' {
      if versioncmp($facts['os']['release']['major'], '10') > 0 {
        $default_mode = '0000'
      } else {
        $default_mode = '0600'
      }
    } else {
      $default_mode = '0000'
    }

    file { '/etc/shadow-':
      ensure => file,
      owner  => 'root',
      group  => $group,
      mode   => pick($mode, $default_mode),
    }
  }
}
