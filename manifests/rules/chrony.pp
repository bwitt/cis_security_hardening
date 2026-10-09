# @summary
#    Ensure chrony is configured
#
# chrony is a daemon which implements the Network Time Protocol (NTP) is designed to synchronize system
# clocks across a variety of systems and use a source that is highly accurate. More information on chrony
# can be found at http://chrony.tuxfamily.org/. chrony can be configured to be a client and/or a server.
#
# Rationale:
# If chrony is in use on the system proper configuration is vital to ensuring time synchronization is working
# properly.
# This recommendation only applies if chrony is in use on the system.
#
# @param enforce
#    Enforce the rule
#
# @param ntp_servers
#    NTP servers to use, add config options per server
#
# @param makestep_seconds
#    Threshold for adjusting system clock.
#
# @param makestep_updates
#    Limit of clock updates since chronyd start.
#
# @example
#   class cis_security_hardening::rules::chrony {
#       enforce => true,
#       ntp_servers => ['server1', 'server2'],
#     }
#   }
#
# @api private
class cis_security_hardening::rules::chrony (
  Boolean $enforce            = false,
  Optional[Chrony::Servers] $ntp_servers = undef,
  Integer $makestep_seconds   = 1,
  Integer $makestep_updates   = 3,
) {
  if $enforce {
    # chrony manages its own options file, so append -u to the flags it sets
    if $facts['os']['family'] == 'RedHat' {
      $distro_options = lookup('chrony::options', Optional[String], 'first', '')
      $chrony_options = empty($distro_options) ? {
        true    => { 'options' => '-u chrony' },
        default => { 'options' => "${distro_options} -u chrony" },
      }
    } else {
      $chrony_options = {}
    }

    class { 'chrony':
      servers          => $ntp_servers,
      makestep_seconds => $makestep_seconds,
      makestep_updates => $makestep_updates,
      *                => $chrony_options,
    }

    case $facts['os']['name'].downcase() {
      'ubuntu': {
        stdlib::ensure_packages(['ntp'], {
          ensure => purged,
        })

        ensure_resource('service', 'systemd-timesyncd', {
          ensure => stopped,
          enable => false,
        })
      }
      default: {
        # nothing to do
      }
    }
  }
}
