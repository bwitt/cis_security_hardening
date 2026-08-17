# @summary
#    Ensure all users last password change date is in the past
#
# All users must have a last password change date in the past. A last change date in the future
# could indicate system clock manipulation, or that an account was created or modified in an
# unusual way.
#
# Rationale:
# If a user's last password change date is in the future, this could indicate that the account
# has been tampered with, thereby granting unauthorized access to the account.
#
# @param enforce
#    Enforce the rule
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
          # lint:ignore:exec_idempotency Idempotency handled by fact check above
          exec { "reset last password change date to today for ${user}":
            command => "chage -d $(date +%Y-%m-%d) ${user}",
            path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
          }
          # lint:endignore
        }
      }
    }
  }
}
