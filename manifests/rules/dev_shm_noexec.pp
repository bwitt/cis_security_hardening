# @summary
#    Ensure noexec option set on /dev/shm partition
#
# The noexec mount option specifies that the filesystem cannot contain executable binaries.
#
# Rationale:
# Setting this option on a file system prevents users from executing programs from shared memory.
# This deters users from introducing potentially malicious software on the system.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::dev_shm_noexec':
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
#
#    Not part of any OS's default bundle - dev_shm's own enforce_noexec
#    parameter covers this by default. Kept as a standalone class for
#    anyone referencing it directly.
class cis_security_hardening::rules::dev_shm_noexec (
  Boolean $enforce = false,
) {
  if ($enforce) and cis_security_hardening::hash_key($facts['mountpoints'], '/dev/shm') and
  cis_security_hardening::hash_key($facts['cis_security_hardening'], 'fstab_mountpoints') and
  cis_security_hardening::hash_key($facts['cis_security_hardening']['fstab_mountpoints'], '/dev/shm') {
    cis_security_hardening::set_mount_options { '/dev/shm-noexec':
      mountpoint   => '/dev/shm',
      mountoptions => 'noexec',
      require      => Class['cis_security_hardening::rules::dev_shm'],
    }
  }
}
