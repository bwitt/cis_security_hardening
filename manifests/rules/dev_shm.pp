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
# @param enforce_nodev
#    Include the nodev option
#
# @param enforce_noexec
#    Include the noexec option
#
# @param enforce_nosuid
#    Include the nosuid option
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
#    explicitly refuses to create a .mount unit or a drop-in for it (see
#    PR discussion). The only mechanism systemd itself provides for
#    customizing its options (systemd-remount-fs.service) reads from
#    /etc/fstab, so this rule manages a fstab entry directly: it creates one
#    if none exists, and replaces the whole line if one already does. This
#    will overwrite any options an administrator had already set there.
class cis_security_hardening::rules::dev_shm (
  Boolean $enforce        = false,
  Integer $size           = 0,
  Boolean $enforce_nodev  = true,
  Boolean $enforce_noexec = true,
  Boolean $enforce_nosuid = true,
) {
  if $enforce {
    $size_token   = $size > 0 ? { true => ["size=${size}G"], false => [] }
    $nodev_token  = $enforce_nodev ? { true => ['nodev'], false => [] }
    $nosuid_token = $enforce_nosuid ? { true => ['nosuid'], false => [] }
    $noexec_token = $enforce_noexec ? { true => ['noexec'], false => [] }
    $options = join(['defaults'] + $size_token + $nodev_token + $nosuid_token + $noexec_token + ['seclabel'], ',')

    $line = "tmpfs   /dev/shm        tmpfs   ${options}   0 0"
    file_line { 'add /dev/shm to fstab':
      ensure             => present,
      path               => '/etc/fstab',
      match              => "^tmpfs\\s* /dev/shm",
      line               => $line,
      append_on_no_match => true,
      notify             => Exec['remount /dev/shm'],
    }

    exec { 'remount /dev/shm':
      command     => 'mount -o remount /dev/shm',  #lint:ignore:security_class_or_define_parameter_in_exec
      path        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      refreshonly => true,
    }
  }
}
