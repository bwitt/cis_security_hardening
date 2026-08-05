# @summary
#    Ensure /dev/shm is configured
#
# /dev/shm is a traditional shared memory concept. One program will create a memory portion, which other processes
# (if permitted) can access. If /dev/shm is not configured, tmpfs will be mounted to /dev/shm by systemd.
#
# Rationale:
# Any user can upload and execute files inside the /dev/shm similar to the /tmp partition. Configuring /dev/shm allows an administrator
# to set the noexec option on the mount, making /dev/shm useless for an attacker to install executable code. It would also prevent an
# attacker from establishing a hardlink to a system setuid program and wait for it to be updated. Once the program was updated, the
# hardlink would be broken and the attacker would have his own copy of the program. If the program happened to have a security
# vulnerability, the attacker could continue to exploit the known flaw.
#
# @param enforce
#    Enforce the rule
#
# @param size
#    Size in GB. 0 leaves the existing size untouched.
#
# @example
#   class { 'cis_security_hardening::rules::dev_shm':
#       enforce => true,
#   }
#
# @api private
#
# @note
#    /dev/shm is one of systemd's "API filesystems" (like /proc, /sys, /run) -
#    it is mounted directly by PID1's early startup code, and systemd
#    explicitly refuses to create a .mount unit for it. The only mechanism
#    systemd itself provides for customizing its options
#    (systemd-remount-fs.service) reads from /etc/fstab, so this rule only
#    applies when /dev/shm already has a real, pre-existing fstab entry - it
#    edits that entry incrementally (rather than replacing it outright) so
#    any other options an administrator has already set are preserved. Hosts
#    without a real entry are left untouched rather than having one
#    fabricated for them.
class cis_security_hardening::rules::dev_shm (
  Boolean $enforce = false,
  Integer $size    = 0,
) {
  if ($enforce) and cis_security_hardening::hash_key($facts['mountpoints'], '/dev/shm') and
  cis_security_hardening::hash_key($facts['cis_security_hardening'], 'fstab_mountpoints') and
  cis_security_hardening::hash_key($facts['cis_security_hardening']['fstab_mountpoints'], '/dev/shm') {
    cis_security_hardening::set_mount_options { '/dev/shm-nodev':
      mountpoint   => '/dev/shm',
      mountoptions => 'nodev',
    }

    cis_security_hardening::set_mount_options { '/dev/shm-noexec':
      mountpoint   => '/dev/shm',
      mountoptions => 'noexec',
    }

    cis_security_hardening::set_mount_options { '/dev/shm-nosuid':
      mountpoint   => '/dev/shm',
      mountoptions => 'nosuid',
    }

    if $size > 0 {
      cis_security_hardening::set_mount_options { '/dev/shm-size':
        mountpoint   => '/dev/shm',
        mountoptions => "size=${size}G",
      }
    }
  }
}
