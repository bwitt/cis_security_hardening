# @summary
#    Ensure nodev option set on /dev/shm partition
#
# The nodev mount option specifies that the filesystem cannot contain special devices.
#
# Rationale:
# Since the /dev/shm filesystem is not intended to support devices, set this option to ensure that users
# cannot attempt to create special devices in /dev/shm partitions.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::dev_shm_nodev':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::dev_shm_nodev (
  Boolean $enforce = false,
) {
  if ($enforce) and cis_security_hardening::hash_key($facts['mountpoints'], '/dev/shm') {
    # /dev/shm is normally kernel/systemd-mounted with no /etc/fstab entry, which
    # set_mount_options requires in order to edit it. Ensure a baseline entry
    # exists first; leave any pre-existing entry (e.g. a configured size) untouched.
    file_line { 'ensure /dev/shm fstab entry exists (nodev)':
      ensure             => present,
      path               => '/etc/fstab',
      match              => '^\S+\s+/dev/shm\s',
      line               => 'tmpfs   /dev/shm        tmpfs   defaults   0 0',
      append_on_no_match => true,
      replace            => false,
      before             => Cis_security_hardening::Set_mount_options['/dev/shm-nodev'],
    }

    cis_security_hardening::set_mount_options { '/dev/shm-nodev':
      mountpoint   => '/dev/shm',
      mountoptions => 'nodev',
      require      => Class['cis_security_hardening::rules::dev_shm'],
    }
  }
}
