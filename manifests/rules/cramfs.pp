# @summary
#    Ensure mounting of cramfs filesystems is disabled
#
# The cramfs filesystem type is a compressed read-only Linux filesystem embedded in small
# footprint systems. A cramfs image can be used without having to first decompress the image.
#
# Rationale:
# Removing support for unneeded filesystem types reduces the local attack surface of the server.
# If this filesystem type is not needed, disable it.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::cramfs':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::cramfs (
  Boolean $enforce = false,
) {
  if $enforce {
    case $facts['os']['name'].downcase() {
      'rocky', 'almalinux', 'centos': {
        kmod::install { 'cramfs':
          command => '/bin/false',
        }
        kmod::blacklist { 'cramfs': }
      }
      'redhat': {
        if versioncmp($facts['os']['release']['major'], '7') > 0 {
          kmod::install { 'cramfs':
            command => '/bin/false',
          }
          kmod::blacklist { 'cramfs': }
        } else {
          kmod::install { 'cramfs':
            command => '/bin/true',
          }
        }
      }
      'debian': {
        if versioncmp($facts['os']['release']['major'], '10') > 0 {
          kmod::install { 'cramfs':
            command => '/bin/false',
          }
          kmod::blacklist { 'cramfs': }
        } else {
          kmod::install { 'cramfs':
            command => '/bin/true',
          }
        }
      }
      'ubuntu': {
        if versioncmp($facts['os']['release']['major'], '20') >= 0 {
          kmod::install { 'cramfs':
            command => '/bin/false',
          }
          kmod::blacklist { 'cramfs': }
        } else {
          kmod::install { 'cramfs':
            command => '/bin/true',
          }
        }
      }
      default: {
        kmod::install { 'cramfs':
          command => '/bin/true',
        }
      }
    }
  }
}
