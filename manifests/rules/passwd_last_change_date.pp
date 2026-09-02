# @summary
#    Alert when a user's last password change date is in the future
#
# All users must have a last password change date in the past. A last change date in the future
# could indicate system clock manipulation, or that an account was created or modified in an
# unusual way.
#
# Rationale:
# If a user's last password change date is in the future, this could indicate that the account
# has been tampered with, thereby granting unauthorized access to the account.
#
# Note: this class only alerts (via a warning-level notify resource that reappears on every
# Puppet run until the underlying condition is corrected) rather than resetting the date
# automatically -- silently rewriting it would erase the evidence needed to investigate the
# anomaly rather than surfacing it.
#
# @param enforce
#    Enable the alert
#
# @example
#   class { 'cis_security_hardening::rules::passwd_last_change_date':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::passwd_last_change_date (
  Boolean $enforce = false,
) {
  if $enforce {
    $local_users = fact('cis_security_hardening.local_users')
    if $local_users != undef {
      $local_users.each | String $user, Hash $attributes | {
        if $attributes['password_date_valid'] == false {
          notify { "user ${user} has a last password change date in the future":
            message  => "CIS: user '${user}' has a last password change date in the future -- investigate for clock manipulation or account tampering",
            loglevel => 'warning',
          }
        }
      }
    }
  }
}
