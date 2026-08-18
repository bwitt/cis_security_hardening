# @summary
#    Ensure accounts without a valid login shell are locked
#
# Accounts provided with most distributions to manage applications are not intended to provide
# an interactive shell. It is important to make sure that accounts not being used by regular
# users are prevented from providing an interactive shell -- if such an account's shell isn't
# set to a valid interactive shell, its password should also be locked.
#
# Rationale:
# An account with an invalid shell that is not locked could still be used to authenticate via
# other means (e.g. SSH key, su), even though it was never intended to provide an interactive
# session.
#
# @param enforce
#    Enforce the rule
#
# @param exclude
#    Accounts to exclude from being locked.
#
# @example
#   class { 'cis_security_hardening::rules::login_shell_lock':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::login_shell_lock (
  Boolean $enforce = false,
  Array $exclude   = [],
) {
  if $enforce {
    $accounts = fact('cis_security_hardening.accounts.no_valid_shell_unlocked')
    if $accounts != undef and !empty($accounts) {
      $accounts.each | String $user | {
        unless $user in $exclude {
          exec { "lock account without a valid login shell: ${user}":
            command => "usermod -L ${user}",
            path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
            onlyif  => "passwd -S ${user} | awk '{print \$2}' | grep -qv '^L'",
          }
        }
      }
    }
  }
}
