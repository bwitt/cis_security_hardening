# @summary
#    Ensure insecure and weak APT repository options are disabled
#
# APT can be told to accept repositories that are unsigned, weakly signed or downgraded, and
# to ignore metadata validity dates. This rule writes a drop-in under /etc/apt/apt.conf.d
# disabling those behaviours. The 99- prefix ensures it takes precedence, as files there are
# processed in lexicographic order.
#
# Rationale:
# Accepting an unsigned or weakly signed repository removes the guarantee that packages come
# from their stated source, allowing an attacker on the network to substitute packages.
#
# @param enforce
#    Enforce the rule
#
# @param config_file
#    The APT configuration drop-in to write
#
# @example
#   class { 'cis_security_hardening::rules::apt_repo_options':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::apt_repo_options (
  Boolean $enforce                  = false,
  Stdlib::Absolutepath $config_file = '/etc/apt/apt.conf.d/99-no-insecure-repositories',
) {
  if $enforce {
    $content = [
      '# This file is managed by Puppet (cis_security_hardening)',
      '# CIS 1.2.1.12 - 1.2.1.15',
      'Acquire::AllowInsecureRepositories "0";',
      'Acquire::AllowWeakRepositories "0";',
      'Acquire::AllowDowngradeToInsecureRepositories "0";',
      'Acquire::Check-Date "true";',
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
