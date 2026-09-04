# @summary
#    Ensure update-notifier-motd.service and update-notifier-motd.timer are not in use
#
# On Ubuntu the update-notifier-common package ships these units to regenerate the dynamic
# message of the day. Masking is preferred over disabling, because disabling only removes
# the enablement symlinks and the companion timer can still activate the unit. Removing the
# update-notifier-common package is not required.
#
# Rationale:
# The dynamic MOTD executes scripts from /etc/update-motd.d at login time, and the update
# and system state it prints discloses more than a login banner should.
#
# @param enforce
#    Enforce the rule
#
# @param units
#    The systemd units to stop and mask
#
# @example
#   class { 'cis_security_hardening::rules::update_notifier_motd':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::update_notifier_motd (
  Boolean $enforce        = false,
  Array[String[1]] $units = ['update-notifier-motd.service', 'update-notifier-motd.timer'],
) {
  if $enforce {
    $units.each |String[1] $unit| {
      exec { "mask ${unit}":
        command => "systemctl stop ${unit} ; systemctl mask ${unit}",
        path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
        onlyif  => "test -e /lib/systemd/system/${unit} -o -e /usr/lib/systemd/system/${unit} -o -e /etc/systemd/system/${unit}",
        unless  => "systemctl is-enabled ${unit} 2>/dev/null | grep -q '^masked'",
        notify  => Exec['systemd-daemon-reload'],
      }
    }
  }
}
