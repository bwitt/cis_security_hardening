# @summary
#    Alert when a group other than root has GID 0
#
# Using GID 0 for the root group helps prevent root group-owned files from accidentally
# becoming accessible to non-privileged users.
#
# Rationale:
# Groups other than the root group with GID 0 could be used to gain unauthorized access to
# files that are group-owned by root.
#
# Note: this class only alerts rather than automatically reassigning a GID -- CIS's own
# remediation for this ("assign them a new GID if appropriate") doesn't specify what GID is
# safe to use, and blindly picking one could break access to files the group legitimately owns.
#
# @param enforce
#    Enable the alert
#
# @example
#   class { 'cis_security_hardening::rules::group_gid_zero':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::group_gid_zero (
  Boolean $enforce = false,
) {
  if $enforce {
    $gid_zero_groups = fact('cis_security_hardening.accounts.gid_zero_groups')
    if $gid_zero_groups != undef and !empty($gid_zero_groups) {
      $gid_zero_groups.each | String $group | {
        notify { "group ${group} has GID 0 but is not root":
          message  => "CIS: group '${group}' has GID 0 but is not the root group -- investigate and reassign to a non-privileged GID",
          loglevel => 'warning',
        }
      }
    }
  }
}
