# @summary
#    Ensure nosuid option set on /dev/shm partition
#
# The nosuid mount option specifies that the filesystem cannot contain setuid files.
#
# Rationale:
# Setting this option on a file system prevents users from introducing privileged programs onto
# the system and allowing non-root users to execute them.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::dev_shm_nosuid':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::dev_shm_nosuid (
  Boolean $enforce = false,
) {
  if ($enforce) and cis_security_hardening::hash_key($facts['mountpoints'], '/dev/shm') {
    # /dev/shm is normally kernel/systemd-mounted with no /etc/fstab entry, which
    # set_mount_options requires in order to edit it. Ensure a baseline entry
    # exists first; leave any pre-existing entry (e.g. a configured size) untouched.
    file_line { 'ensure /dev/shm fstab entry exists (nosuid)':
      ensure             => present,
      path               => '/etc/fstab',
      match              => '^\S+\s+/dev/shm\s',
      line               => 'tmpfs   /dev/shm        tmpfs   defaults   0 0',
      append_on_no_match => true,
      replace            => false,
      before             => Cis_security_hardening::Set_mount_options['/dev/shm-nosuid'],
    }

    cis_security_hardening::set_mount_options { '/dev/shm-nosuid':
      mountpoint   => '/dev/shm',
      mountoptions => 'nosuid',
      require      => Class['cis_security_hardening::rules::dev_shm'],
    }
  }
}
