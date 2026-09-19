# @summary
#    Ensure network file system services are not in use
#
# The Network File System (NFS) is one of the first and most widely distributed file systems in the UNIX
# environment. It provides the ability for systems to mount file systems of other servers through the network.
#
# Rationale:
# If the system does not export NFS shares, it is recommended that the NFS be disabled to reduce the remote attack
# surface.
#
# Note: many of the libvirt packages used by Enterprise Linux virtualization are dependent on the nfs-utils package.
# If the nfs package is required as a dependency, set `uninstall` to false. The nfs-server service is then stopped
# and masked instead of the package being removed.
#
# @param enforce
#    Enforce the rule
#
# @param uninstall
#    Remove the NFS server package. When false, the nfs-server service is stopped and masked instead, for hosts
#    where the package has to stay installed as a dependency.
#
# @example
#   class { 'cis_security_hardening::rules::nfs':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::nfs (
  Boolean $enforce   = false,
  Boolean $uninstall = true,
) {
  if $enforce {
    if $uninstall {
      # The server package differs per OS family, and so does the sensible removal
      # mode: purge also drops the config on Debian derivatives.
      case $facts['os']['family'].downcase() {
        'redhat': {
          $packages   = ['nfs-utils']
          $pkg_ensure = 'absent'
        }
        'suse': {
          $packages   = ['nfs-utils', 'nfs-kernel-server']
          $pkg_ensure = 'absent'
        }
        default: {
          $packages   = ['nfs-kernel-server']
          $pkg_ensure = 'purged'
        }
      }

      # Removing the package stops the service as part of the package manager's
      # own removal scripts, so the service is deliberately not managed here.
      stdlib::ensure_packages($packages, {
        ensure => $pkg_ensure,
      })
    } else {
      ensure_resource('service', 'nfs-server', {
        ensure => stopped,
        enable => false,
      })

      exec { 'mask nfs-server service':
        command => 'systemctl --now mask nfs-server',
        path    => ['/usr/bin', '/bin'],
        unless  => 'test "$(systemctl is-enabled nfs-server)" = "masked"',
      }
    }
  }
}
