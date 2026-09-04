# @summary
#    Ensure sudo log file exists
#
# sudo logs successful and unsuccessful privilege escalation attempts. Classic sudo supports
# a Defaults logfile= entry, sudo-rs does not: it silently ignores the option and always
# emits events to syslog under the authpriv facility. sudo-rs is the default implementation
# on Ubuntu 26.04 and later, so those systems need the syslog method.
#
# Rationale:
# A durable record of sudo invocations simplifies forensic investigation of privilege
# escalation events and supports compliance auditing.
#
# @param enforce
#    Enforce the rule
#
# @param log_method
#    Capture events with a Defaults logfile= entry or with an rsyslog rule
#
# @param log_file
#    The file sudo events are written to
#
# @example
#   class { 'cis_security_hardening::rules::sudo_log':
#       enforce    => true,
#       log_method => 'syslog',
#   }
#
# @api private
class cis_security_hardening::rules::sudo_log (
  Boolean $enforce                      = false,
  Enum['logfile', 'syslog'] $log_method = 'logfile',
  Stdlib::Absolutepath $log_file        = '/var/log/sudo.log',
) {
  if $enforce {
    case $log_method {
      'syslog': {
        file { '/etc/rsyslog.d/30-sudo.conf':
          ensure  => file,
          owner   => 'root',
          group   => 'root',
          mode    => '0640',
          content => "# CIS 5.2.3 - durable sudo event capture\nauthpriv.*\t\t\t\t${log_file}\n",
          notify  => Exec['reload-rsyslog'],
        }

        file { $log_file:
          ensure => file,
          owner  => 'root',
          group  => 'adm',
          mode   => '0640',
        }
      }
      default: {
        file_line { 'sudo logfile':
          path               => '/etc/sudoers',
          match              => 'Defaults.*logfile\s*=',
          append_on_no_match => true,
          line               => "Defaults\tlogfile=\"${log_file}\"",
          after              => '# Defaults specification',
        }
      }
    }
  }
}
