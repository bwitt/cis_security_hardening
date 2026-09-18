# @summary
#    CIS benchmark enforcement
#
# Implements the CIS benchmarks and enforces them by default. The module ships the benchmark definitions for every supported OS in
# its own Hiera layer, so including this class applies that OS's benchmark with no further configuration.
#
# Override rules or the level in your own Hiera, which takes precedence. See the README for details.
#
# @param profile
#    Benchmark profile. Only the CIS server profiles are implemented.
# @param level
#    CIS benchmark level: `1` for level 1 server, `2` for level 2 server, `stig` for the CIS STIG benchmark. Levels are cumulative.
#    The module's Hiera data sets `2` for every supported OS. `stig` only adds rules on RedHat 7, 8, 9 and Ubuntu 20.04; elsewhere
#    it behaves like `2`.
# @param update_postrun_command
#    Update Puppet agent post run command
# @param fact_upload_command
#    Command to use to upload facts to Puppet master
# @param exclude_dirs_sticky_ww
#    Araay of directories to exclude from the search for world writable directories with sticky bit
# @param auditd_dirs_to_include
#    Directories to search for privileged commands to create auditd rules.
# @param time_until_reboot
#    Time to wait until system is rebooted if required. Time in seconds. For `reboot` the `puppetlabs-reboot` module is used. Please obey
#    the following comment from this module: POSIX systems (with the exception of Solaris) only support
#    specifying the timeout as minutes. As such, the value of timeout must be a multiple of 60. Other values will be rounded up to the
#    nearest minute and a warning will be issued.
# @param auto_reboot
#    Reboot when necessary after `time_until_reboot` is exceeded
# @param verbose_logging
#    Print various info messages
# @param remove_authconfig
#    remove authconfig package on Redhat 7 or similar OSes
# @param enable_sticky_world_writable_cron
#   Whether to enable the sticky world writable cron job.
# @param enable_auditd_cron
#   Whether to enable the auditd cron job.
#
# @example
#   include cis_security_hardening
class cis_security_hardening (
  Enum['server'] $profile                   = 'server',
  Enum['1', '2', 'stig'] $level             = '2',
  Array $exclude_dirs_sticky_ww             = [],
  Array $auditd_dirs_to_include             = ['/usr'],
  Boolean $update_postrun_command           = true,
  Stdlib::Absolutepath $fact_upload_command = '/usr/share/cis_security_hardening/bin/fact_upload.sh',
  Integer $time_until_reboot                = 120,
  Boolean $auto_reboot                      = true,
  Boolean $verbose_logging                  = false,
  Boolean $remove_authconfig                = false,
  Boolean $enable_sticky_world_writable_cron = true,
  Boolean $enable_auditd_cron               = true,
) {
  contain cis_security_hardening::reboot
  contain cis_security_hardening::services

  $base_dir = '/usr/share/cis_security_hardening'

  if $remove_authconfig and $facts['os']['family'].downcase() == 'redhat' and $facts['os']['release']['major'] == '7' {
    $ensure = $facts['os']['family'].downcase() ? {
      'suse'  => 'absent',
      default => 'purged',
    }
    stdlib::ensure_packages(['authconfig'], {
      ensure => $ensure,
    })
  }

  class { 'cis_security_hardening::sticky_world_writable_cron':
    ensure          => stdlib::ensure($enable_sticky_world_writable_cron),
    dirs_to_exclude => $exclude_dirs_sticky_ww,
    filename        => "${base_dir}/data/world-writable-files.txt",
    script          => "${base_dir}/bin/sticy-world-writable.sh",
  }

  class { 'cis_security_hardening::auditd_cron':
    ensure          => stdlib::ensure($enable_auditd_cron),
    dirs_to_include => $auditd_dirs_to_include,
    output_file     => "${base_dir}/data/auditd_priv_cmds.txt",
    script          => "${base_dir}/bin/auditd_priv_cmds.sh",
  }

  class { 'cis_security_hardening::config':
    base_dir               => $base_dir,
    update_postrun_command => $update_postrun_command,
    fact_upload_command    => $fact_upload_command,
  }

  $os = fact('os.name') ? {
    undef   => 'unknown',
    default => fact('os.name').downcase()
  }

  $os_maj = fact('os.release.major') ? {
    undef   => 'unknown',
    default => fact('os.release.major'),
  }
  $os_vers = $os ? {
    'ubuntu' => split($os_maj, '[.]')[0],
    default  => $os_maj,
  }

  $key = "cis_security_hardening::benchmark::${os}::v${os_vers}"
  $benchmark = lookup($key, undef, undef, {})

  if cis_security_hardening::hash_key($benchmark, 'bundles') {
    $benchmark['bundles'].each |$bundle, $bundle_data| {
      $level1 = cis_security_hardening::hash_key($bundle_data, 'level1') ? {
        true  => $bundle_data['level1'],
        false => [],
      }

      $level2 = cis_security_hardening::hash_key($bundle_data, 'level2') ? {
        true  => $bundle_data['level2'],
        false => [],
      }

      $stig = cis_security_hardening::hash_key($bundle_data, 'stig') ? {
        true => $bundle_data['stig'],
        false => [],
      }

      $rules = $level ? {
        '1' => $level1,
        '2' => concat($level1, $level2),
        'stig' => concat($level1, $level2, $stig)
      }

      if $verbose_logging {
        echo { "cis_security_hardening applying bundle ${bundle}":
          message  => "cis_security_hardening applying bundle ${bundle}",
          loglevel => 'info',
          withpath => false,
        }
      }

      $rules.each |$rule| {
        $class = "cis_security_hardening::rules::${rule}"

        if $verbose_logging {
          echo { "Applying ${class}":
            message  => "Applying ${class}",
            loglevel => 'info',
            withpath => false,
          }
        }

        include $class
      }
    }
  } else {
    fail("No bundles found for this OS. Expected to find bundles at hiera key: ${key}")
  }
}
