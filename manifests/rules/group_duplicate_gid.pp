# @summary
#    Alert when a GID is shared by more than one group
#
# The groupadd program will not let you create a duplicate GID, but an administrator can
# manually edit /etc/group and assign the same GID to multiple groups. Groups must be assigned
# unique GIDs for accountability and to ensure appropriate access protections.
#
# Rationale:
# Groups sharing a GID are effectively the same group for file-ownership and access-control
# purposes, which breaks accountability.
#
# Note: this class only alerts rather than automatically reassigning a GID -- CIS's own
# remediation is "establish unique GIDs and review all files owned by the shared GID," which
# requires manual investigation, not something safe to automate.
#
# @param enforce
#    Enable the alert
#
# @example
#   class { 'cis_security_hardening::rules::group_duplicate_gid':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::group_duplicate_gid (
  Boolean $enforce = false,
) {
  if $enforce {
    $duplicates = fact('cis_security_hardening.accounts.duplicate_gids')
    if $duplicates != undef and !empty($duplicates) {
      $duplicates.each | String $gid, Array $groups | {
        $group_list = join($groups, ', ')
        notify { "duplicate GID ${gid}":
          message  => "CIS: GID '${gid}' is shared by multiple groups (${group_list}) -- investigate and assign unique GIDs",
          loglevel => 'warning',
        }
      }
    }
  }
}
