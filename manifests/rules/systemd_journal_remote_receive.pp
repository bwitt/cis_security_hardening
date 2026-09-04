# @summary
#    Ensure systemd-journal-remote service is not in use
#
# systemd-journal-remote listens for journal records forwarded by systemd-journal-upload on
# other hosts. Masking is preferred over disabling, because disabling only removes the
# enablement symlinks and the unit can still be activated through its socket.
#
# Rationale:
# A listening journal receiver accepts log data from the network. If it is not needed it is
# an unnecessary listening service, and if misconfigured it allows forged journal records.
#
# @param enforce
#    Enforce the rule
#
# @param mask
#    Mask the units instead of only stopping and disabling them
#
# @param units
#    The units to stop, and to mask when mask is true
#
# @example
#   class { 'cis_security_hardening::rules::systemd_journal_remote_receive':
#       enforce => true,
#       mask    => true,
#   }
#
# @api private
class cis_security_hardening::rules::systemd_journal_remote_receive (
  Boolean $enforce        = false,
  Boolean $mask           = false,
  Array[String[1]] $units = ['systemd-journal-remote.socket'],
) {
  if $enforce {
    $units.each |String[1] $unit| {
      service { $unit:
        ensure => stopped,
        enable => false,
      }

      if $mask {
        exec { "mask ${unit}":
          command => "systemctl mask ${unit}",
          path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
          unless  => "systemctl is-enabled ${unit} 2>/dev/null | grep -q '^masked'",
          require => Service[$unit],
          notify  => Exec['systemd-daemon-reload'],
        }
      }
    }
  }
}
