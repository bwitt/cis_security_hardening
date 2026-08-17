# @summary
#    Ensure /etc/shadow password fields are not empty
#
# An account with an empty password field means that anybody may log in as that user without
# providing a password.
#
# Rationale:
# All accounts must have passwords or be locked to prevent the account from being used by an
# unauthorized user.
#
# @param enforce
#    Enforce the rule
#
# @param exclude
#    Accounts to exclude from being locked.
#
# @example
#   class { 'cis_security_hardening::rules::shadow_password_empty':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::shadow_password_empty (
  Boolean $enforce = false,
  Array $exclude   = [],
) {
  if $enforce {
    $empty_password = fact('cis_security_hardening.accounts.empty_password')
    if $empty_password != undef and !empty($empty_password) {
      $empty_password.each | String $user | {
        unless $user in $exclude {
          # lint:ignore:exec_idempotency Idempotency handled by fact check above
          exec { "lock account with empty password: ${user}":
            command => "passwd -l ${user}",
            path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
          }
          # lint:endignore
        }
      }
    }
  }
}
