# @summary
#    Alert when an account other than root has GID 0 as its primary group
#
# Using GID 0 for the root account helps prevent root-owned files from accidentally becoming
# accessible to non-privileged users. This is a distinct check from
# `cis_security_hardening::rules::root_gid`, which only ensures root's own primary group is
# GID 0 -- it does not detect other accounts also using GID 0.
#
# Note: `sync`, `shutdown`, `halt`, and `operator` are excluded, matching common distro
# defaults that intentionally share root's group.
#
# Rationale:
# Accounts with GID 0 can create files that are group-owned by root, which may grant them
# unintended access to files intended to be restricted to root.
#
# Note: this class only alerts rather than automatically reassigning a GID -- CIS's own
# remediation for this ("assign them a new GID if appropriate") doesn't specify what GID is
# safe to use, and blindly picking one could break access to files the account's group
# legitimately owns.
#
# @param enforce
#    Enable the alert
#
# @example
#   class { 'cis_security_hardening::rules::passwd_gid_zero':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::passwd_gid_zero (
  Boolean $enforce = false,
) {
  if $enforce {
    $gid_zero = fact('cis_security_hardening.accounts.gid_zero')
    if $gid_zero != undef and !empty($gid_zero) {
      $gid_zero.each | String $user | {
        notify { "user ${user} has GID 0 but is not root":
          message  => "CIS: user '${user}' has GID 0 as its primary group but is not root -- investigate and reassign to a non-privileged GID",
          loglevel => 'warning',
        }
      }
    }
  }
}
