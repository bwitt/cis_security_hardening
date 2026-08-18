# @summary
#    Alert when an account other than root has UID 0
#
# Any account with UID 0 has superuser privileges on the system. This access must be limited
# to only the default root account and only from the system console.
#
# Rationale:
# This access must be limited to only the default root account and only from the system
# console. Administrative access must be through an unprivileged account using an approved
# mechanism.
#
# Note: this class only alerts rather than automatically reassigning a UID -- CIS's own
# remediation for this ("assign them a new UID") doesn't specify what UID is safe to use, and
# blindly picking one could collide with an existing UID or orphan every file the account owns.
#
# @param enforce
#    Enable the alert
#
# @example
#   class { 'cis_security_hardening::rules::passwd_uid_zero':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::passwd_uid_zero (
  Boolean $enforce = false,
) {
  if $enforce {
    $uid_zero = fact('cis_security_hardening.accounts.uid_zero')
    if $uid_zero != undef and !empty($uid_zero) {
      $uid_zero.each | String $user | {
        notify { "user ${user} has UID 0 but is not root":
          message  => "CIS: user '${user}' has UID 0 but is not root -- investigate and reassign to an unprivileged UID",
          loglevel => 'warning',
        }
      }
    }
  }
}
