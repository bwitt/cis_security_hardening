# @summary
#    Ensure packet forwarding on network interfaces is disabled
#
# Setting net.ipv4.conf.all.forwarding, net.ipv4.conf.default.forwarding and their IPv6
# equivalents to 0 prevents the system from forwarding packets between interfaces. This
# complements the global net.ipv4.ip_forward setting by also covering the per-interface
# "all" and "default" configuration keys.
#
# Rationale:
# Setting these parameters to 0 ensures that a system with multiple interfaces (for example
# a system with more than one NIC or with virtual interfaces) will not act as a router
# unless that role is explicitly intended. Routing on a host that is not a router can be
# used to bypass network segmentation and firewall policy.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::interface_ip_forwarding':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::interface_ip_forwarding (
  Boolean $enforce = false,
) {
  if $enforce {
    sysctl { 'net.ipv4.conf.all.forwarding':
      ensure => present,
      value  => 0,
    }

    sysctl { 'net.ipv4.conf.default.forwarding':
      ensure => present,
      value  => 0,
    }

    if fact('network6') {
      sysctl {
        'net.ipv6.conf.default.forwarding':
          ensure => present,
          value  => 0,
      }
    }
  }
}
