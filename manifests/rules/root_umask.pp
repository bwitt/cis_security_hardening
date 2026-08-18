# @summary
#    Ensure root user umask is configured
#
# The user file-creation mode mask (umask) determines the permissions of files and directories
# newly created by root. Setting a restrictive umask in root's own shell configuration files
# ensures newly created files aren't inadvertently accessible to non-privileged users.
#
# This is distinct from `cis_security_hardening::rules::umask_setting`, which manages the
# system-wide default umask for regular interactive users (`/etc/login.defs`,
# `/etc/profile.d/set_umask.sh`, etc.) -- root reads its own `.bash_profile`/`.bashrc` instead,
# which `umask_setting` does not touch.
#
# @param enforce
#    Enforce the rule
#
# @param default_umask
#    Default umask to set for root.
#
# @example
#   class { 'cis_security_hardening::rules::root_umask':
#     enforce => true,
#     default_umask => '027',
#   }
#
# @api private
class cis_security_hardening::rules::root_umask (
  Boolean $enforce      = false,
  String $default_umask = '027',
) {
  if $enforce {
    ensure_resource('file', '/root/.bash_profile', {
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
    })

    file_line { 'root umask bash_profile':
      path               => '/root/.bash_profile',
      line               => "umask ${default_umask}",
      match              => '^\s*umask\s+\d+',
      append_on_no_match => true,
      require            => File['/root/.bash_profile'],
    }

    file_line { 'root umask bashrc':
      path               => '/root/.bashrc',
      line               => "umask ${default_umask}",
      match              => '^\s*umask\s+\d+',
      append_on_no_match => true,
    }
  }
}
