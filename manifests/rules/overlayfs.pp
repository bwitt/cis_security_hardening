# @summary
#    Ensure overlayfs kernel module is not available
#
# The overlay filesystem combines multiple different directories into a single directory. It is commonly
# used for containers and package management systems. The overlayfs filesystem type allows one, usually
# read-write, directory tree to be overlaid onto another, read-only directory tree.
#
# Rationale:
# Removing support for unneeded filesystem types reduces the local attack surface of the system. If this
# filesystem type is not needed, disable it.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::overlayfs':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::overlayfs (
  Boolean $enforce = false,
) {
  if $enforce {
    case $facts['os']['name'].downcase() {
      'rocky', 'almalinux', 'centos': {
        kmod::install { 'overlay':
          command => '/bin/false',
        }
        kmod::blacklist { 'overlay': }
      }
      'redhat': {
        if versioncmp($facts['os']['release']['major'], '7') > 0 {
          kmod::install { 'overlay':
            command => '/bin/false',
          }
          kmod::blacklist { 'overlay': }
        } else {
          kmod::install { 'overlay':
            command => '/bin/true',
          }
        }
      }
      'debian': {
        if versioncmp($facts['os']['release']['major'], '10') > 0 {
          kmod::install { 'overlay':
            command => '/bin/false',
          }
          kmod::blacklist { 'overlay': }
        } else {
          kmod::install { 'overlay':
            command => '/bin/true',
          }
        }
      }
      'ubuntu': {
        if versioncmp($facts['os']['release']['major'], '20') >= 0 {
          kmod::install { 'overlay':
            command => '/bin/false',
          }
          kmod::blacklist { 'overlay': }
        } else {
          kmod::install { 'overlay':
            command => '/bin/true',
          }
        }
      }
      default: {
        kmod::install { 'overlay':
          command => '/bin/true',
        }
      }
    }
  }
}
