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
#    Size in GB
#
# @example
#   class { 'cis_security_hardening::rules::dev_shm':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::dev_shm (
  Boolean $enforce = false,
  Integer $size    = 0,
) {
  if $enforce {
    # Create the entry only when missing; nodev, nosuid and noexec are added by their own rules
    augeas { 'add /dev/shm to fstab':
      context => '/files/etc/fstab',
      changes => [
        'set 01/spec tmpfs',
        'set 01/file /dev/shm',
        'set 01/vfstype tmpfs',
        'set 01/opt defaults',
        'set 01/dump 0',
        'set 01/passno 0',
      ],
      onlyif  => "match *[file = '/dev/shm'] size == 0",
    }

    if $size > 0 {
      cis_security_hardening::set_mount_options { '/dev/shm-size':
        mountpoint   => '/dev/shm',
        mountoptions => "size=${size}G",
        require      => Augeas['add /dev/shm to fstab'],
      }
    }

    # seclabel is only a valid mount option where SELinux is active
    if fact('os.selinux.enabled') {
      cis_security_hardening::set_mount_options { '/dev/shm-seclabel':
        mountpoint   => '/dev/shm',
        mountoptions => 'seclabel',
        require      => Augeas['add /dev/shm to fstab'],
      }
    }
  }
}
