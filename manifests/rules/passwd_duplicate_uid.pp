# @summary
#    Alert when a UID is shared by more than one account
#
# The useradd program will not let you create a duplicate UID, but an administrator can
# manually edit /etc/passwd and assign the same UID to multiple accounts. Users must be
# assigned unique UIDs for accountability and to ensure appropriate access protections.
#
# Rationale:
# Accounts sharing a UID are effectively the same account for file-ownership and access-control
# purposes, which breaks accountability.
#
# Note: this class only alerts rather than automatically reassigning a UID -- CIS's own
# remediation is "establish unique UIDs and review all files owned by the shared UIDs," which
# requires manual investigation, not something safe to automate.
#
# @param enforce
#    Enable the alert
#
# @example
#   class { 'cis_security_hardening::rules::passwd_duplicate_uid':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::passwd_duplicate_uid (
  Boolean $enforce = false,
) {
  if $enforce {
    $duplicates = fact('cis_security_hardening.accounts.duplicate_uids')
    if $duplicates != undef and !empty($duplicates) {
      $duplicates.each | String $uid, Array $users | {
        $user_list = join($users, ', ')
        notify { "duplicate UID ${uid}":
          message  => "CIS: UID '${uid}' is shared by multiple accounts (${user_list})",
          loglevel => 'warning',
        }
      }
    }
  }
}
