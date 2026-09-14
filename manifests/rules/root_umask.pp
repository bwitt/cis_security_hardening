# @summary
#    Ensure root user umask is configured
#
# The user file-creation mode mask (umask) determines the permissions of files and directories newly
# created by root. Setting a restrictive umask in root's own shell configuration files ensures that
# newly created files are not inadvertently accessible to non-privileged users.
#
# Note: This is distinct from cis_security_hardening::rules::umask_setting, which manages the system
# wide default umask for regular interactive users (/etc/login.defs, /etc/profile.d/set_umask.sh and
# similar). Root reads its own login profile and .bashrc, which umask_setting does not touch. The name
# of that login profile is OS dependent, because bash sources only the first of .bash_profile,
# .bash_login and .profile that exists. Red Hat based systems ship /root/.bash_profile while Debian
# and SUSE based systems ship /root/.profile, so the umask line is added to the file the platform
# actually uses rather than creating one that shadows it.
#
# Rationale:
# Files and directories created by root while administering the system inherit root's umask. A
# permissive umask leaves configuration files, logs and scripts readable or even writable by
# unprivileged users, which can disclose sensitive information or let a local user influence what
# root executes later on. A umask of 027 denies all access to other users and write access to the
# group, so files created by root are restricted by default.
#
# @param enforce
#    Enforce the rule
#
# @param default_umask
#    Default umask to set for root.
#
# @example
#   class { 'cis_security_hardening::rules::root_umask':
#       enforce => true,
#       default_umask => '027',
#   }
#
# @api private
class cis_security_hardening::rules::root_umask (
  Boolean $enforce      = false,
  String $default_umask = '027',
) {
  if $enforce {
    $root_profile = $facts['os']['family'].downcase() ? {
      'debian' => '/root/.profile',
      'suse'   => '/root/.profile',
      default  => '/root/.bash_profile',
    }

    ensure_resource('file', $root_profile, {
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
    })

    file_line { 'root umask profile':
      path               => $root_profile,
      line               => "umask ${default_umask}",
      match              => '^\s*umask\s+\d+',
      append_on_no_match => true,
      require            => File[$root_profile],
    }

    ensure_resource('file', '/root/.bashrc', {
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
    })

    file_line { 'root umask bashrc':
      path               => '/root/.bashrc',
      line               => "umask ${default_umask}",
      match              => '^\s*umask\s+\d+',
      append_on_no_match => true,
      require            => File['/root/.bashrc'],
    }
  }
}
