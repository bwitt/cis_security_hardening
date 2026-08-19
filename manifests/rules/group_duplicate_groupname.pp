# @summary
#    Alert when a group name is shared by more than one group
#
# The groupadd program will not let you create a duplicate group name, but an administrator can
# manually edit /etc/group and assign the same name to multiple groups. If a group name is
# duplicated, referencing that name always resolves to the first matching entry's GID,
# effectively sharing that GID.
#
# Rationale:
# A duplicated group name silently shares access with whichever group comes first in
# /etc/group, which is a security problem even if the GIDs themselves are unique.
#
# Note: this class only alerts rather than automatically renaming a group -- CIS's own
# remediation is "establish unique names for the user groups," which requires manual review,
# not something safe to automate.
#
# @param enforce
#    Enable the alert
#
# @example
#   class { 'cis_security_hardening::rules::group_duplicate_groupname':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::group_duplicate_groupname (
  Boolean $enforce = false,
) {
  if $enforce {
    $duplicates = fact('cis_security_hardening.accounts.duplicate_groupnames')
    if $duplicates != undef and !empty($duplicates) {
      $duplicates.each | String $group | {
        notify { "duplicate group name ${group}":
          message  => "CIS: group name '${group}' appears more than once in /etc/group -- investigate and assign unique group names",
          loglevel => 'warning',
        }
      }
    }
  }
}
