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
#
# @note
#    This rule only applies when /dev/shm already has an explicit entry in
#    /etc/fstab. set_mount_options edits an existing fstab line rather than
#    creating one, and /dev/shm is mounted by the kernel/systemd without an
#    fstab entry on many systems - so without this check the rule would fail
#    to apply there instead of silently skipping.
#
#    Not part of any OS's default bundle - dev_shm's own enforce_nosuid
#    parameter covers this by default. Kept as a standalone class for
#    anyone referencing it directly.
class cis_security_hardening::rules::dev_shm_nosuid (
  Boolean $enforce = false,
) {
  if ($enforce) and cis_security_hardening::hash_key($facts['mountpoints'], '/dev/shm') and
  cis_security_hardening::hash_key($facts['cis_security_hardening'], 'fstab_mountpoints') and
  cis_security_hardening::hash_key($facts['cis_security_hardening']['fstab_mountpoints'], '/dev/shm') {
    cis_security_hardening::set_mount_options { '/dev/shm-nosuid':
      mountpoint   => '/dev/shm',
      mountoptions => 'nosuid',
      require      => Class['cis_security_hardening::rules::dev_shm'],
    }
  }
}
