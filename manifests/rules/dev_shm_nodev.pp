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
#
# @note
#    This rule only applies when /dev/shm already has an explicit entry in
#    /etc/fstab. set_mount_options edits an existing fstab line rather than
#    creating one, and /dev/shm is mounted by the kernel/systemd without an
#    fstab entry on many systems - so without this check the rule would fail
#    to apply there instead of silently skipping.
class cis_security_hardening::rules::dev_shm_nodev (
  Boolean $enforce = false,
) {
  if ($enforce) and cis_security_hardening::hash_key($facts['mountpoints'], '/dev/shm') and
  cis_security_hardening::hash_key($facts['cis_security_hardening'], 'fstab_mountpoints') and
  cis_security_hardening::hash_key($facts['cis_security_hardening']['fstab_mountpoints'], '/dev/shm') {
    cis_security_hardening::set_mount_options { '/dev/shm-nodev':
      mountpoint   => '/dev/shm',
      mountoptions => 'nodev',
      require      => Class['cis_security_hardening::rules::dev_shm'],
    }
  }
}
