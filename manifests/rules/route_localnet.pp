# @summary
#    Ensure net.ipv4.conf.all.route_localnet is disabled
#
# The net.ipv4.conf.all.route_localnet kernel parameter controls whether the 127/8 loopback
# range may be used as a source or destination for routed traffic. Setting it to 0 restores
# the standard behaviour of treating loopback addresses as martian outside the host.
#
# Rationale:
# Allowing the loopback network to be routed lets an attacker reach services that are bound
# only to 127.0.0.1 and are therefore assumed to be host-local. Disabling route_localnet
# keeps loopback-bound services unreachable from the network.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::route_localnet':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::route_localnet (
  Boolean $enforce = false,
) {
  if $enforce {
    sysctl { 'net.ipv4.conf.all.route_localnet':
      ensure => present,
      value  => 0,
    }
  }
}
