# @summary
#    Ensure iptables-persistent is not installed with ufw
#
# The iptables-persistent package is a boot-time loader for netfilter rules, an
# iptables plugin.
#
# Rationale:
# Running both ufw and the services included in the iptables-persistent package may
# lead to conflict.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::iptables_persistent':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::iptables_persistent (
  Boolean $enforce = false,
) {
  if $enforce {
    $ufw_enforced = lookup('cis_security_hardening::rules::ufw_install::enforce', Boolean, 'first', false)

    if $ufw_enforced {
      $ensure = $facts['os']['family'].downcase() ? {
        'suse'  => 'absent',
        default => 'purged',
      }

      stdlib::ensure_packages(['iptables-persistent'], {
        ensure => $ensure,
      })
    }
  }
}
