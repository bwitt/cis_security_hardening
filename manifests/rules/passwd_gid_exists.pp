# @summary
#    Alert when a user's GID does not exist in /etc/group
#
# Over time, system administration errors and changes can lead to groups being referenced in
# /etc/passwd but not defined in /etc/group. Accounts whose primary GID doesn't exist pose a
# threat to system security since group permissions are not properly managed.
#
# Rationale:
# Group permissions are not properly managed for accounts whose primary group doesn't exist.
#
# Note: this class only alerts rather than automatically correcting the GID -- CIS's own
# remediation is "perform the appropriate action to correct any discrepancies found," which
# doesn't specify a safe target group, and blindly picking one could grant or deny access the
# account wasn't supposed to have.
#
# @param enforce
#    Enable the alert
#
# @example
#   class { 'cis_security_hardening::rules::passwd_gid_exists':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::passwd_gid_exists (
  Boolean $enforce = false,
) {
  if $enforce {
    $orphans = fact('cis_security_hardening.accounts.orphan_gid_users')
    if $orphans != undef and !empty($orphans) {
      $orphans.each | String $user | {
        notify { "user ${user} has a GID that does not exist in /etc/group":
          message  => "CIS: user '${user}' has a GID in /etc/passwd with no matching entry in /etc/group -- investigate and correct",
          loglevel => 'warning',
        }
      }
    }
  }
}
