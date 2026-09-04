# @summary
#    Ensure APT weak dependencies are not installed
#
# APT installs recommended and suggested packages by default. This rule writes a drop-in
# under /etc/apt/apt.conf.d disabling both.
#
# Rationale:
# Every additional package adds to the attack surface and the patching burden without having
# been explicitly requested.
#
# @param enforce
#    Enforce the rule
#
# @param config_file
#    The APT configuration drop-in to write
#
# @example
#   class { 'cis_security_hardening::rules::apt_weak_dependencies':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::apt_weak_dependencies (
  Boolean $enforce                  = false,
  Stdlib::Absolutepath $config_file = '/etc/apt/apt.conf.d/60-no-weak-dependencies',
) {
  if $enforce {
    $content = [
      '# This file is managed by Puppet (cis_security_hardening)',
      '# CIS 1.2.1.2',
      'APT::Install-Recommends "0";',
      'APT::Install-Suggests "0";',
      '',
    ].join("\n")

    file { $config_file:
      ensure  => file,
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
      content => $content,
    }
  }
}
