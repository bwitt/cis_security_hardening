# @summary
#    Alert when a user name is shared by more than one account
#
# The useradd program will not let you create a duplicate user name, but an administrator can
# manually edit /etc/passwd and assign the same name to multiple accounts. If a user name is
# duplicated, logging in with that name always resolves to the first matching entry's UID,
# effectively sharing that UID.
#
# Rationale:
# A duplicated user name silently shares access with whichever account comes first in
# /etc/passwd, which is a security problem even if the UIDs themselves are unique.
#
# Note: this class only alerts rather than automatically renaming an account -- CIS's own
# remediation is "establish unique user names for the users," which requires manual review,
# not something safe to automate.
#
# @param enforce
#    Enable the alert
#
# @example
#   class { 'cis_security_hardening::rules::passwd_duplicate_username':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::passwd_duplicate_username (
  Boolean $enforce = false,
) {
  if $enforce {
    $duplicates = fact('cis_security_hardening.accounts.duplicate_usernames')
    if $duplicates != undef and !empty($duplicates) {
      $duplicates.each | String $user | {
        notify { "duplicate username ${user}":
          message  => "CIS: username '${user}' appears more than once in /etc/passwd",
          loglevel => 'warning',
        }
      }
    }
  }
}
