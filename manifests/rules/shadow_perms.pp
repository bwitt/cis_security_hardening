# @summary
#    Ensure permissions on /etc/shadow are configured
#
# The /etc/shadow file is used to store the information about user accounts that is critical to the security
# of those accounts, such as the hashed password and other security information.
#
# Rationale:
# If attackers can gain read access to the /etc/shadow file, they can easily run a password cracking program
# against the hashed password to break it. Other security information that is stored in the /etc/shadow
# file (such as expiration) could also be useful to subvert the user accounts.
#
# @param enforce
#    Enforce the rule
#
# @param mode
#    File mode to enforce. The benchmark asks for 0640 or more restrictive.
#
# @param group
#    Group owner to enforce. The benchmark allows either root or shadow.
#    Note that setting this to root removes access for setgid-shadow helpers
#    such as unix_chkpwd, which non-root PAM uses to read /etc/shadow.
#
# @example
#   class { 'cis_security_hardening::rules::shadow_perms':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::shadow_perms (
  Boolean                             $enforce = false,
  Cis_security_hardening::Shadowmode  $mode    = '0000',
  Cis_security_hardening::Shadowgroup $group   = 'root',
) {
  if $enforce {
    file { '/etc/shadow':
      ensure => file,
      owner  => 'root',
      group  => $group,
      mode   => $mode,
    }
  }
}
