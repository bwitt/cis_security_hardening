# @summary
#    Ensure access to APT gpg key files and keyring directories is configured
#
# APT verifies repository metadata against the gpg keys in /etc/apt/trusted.gpg.d and
# /usr/share/keyrings. Both directories and the key files in them must be owned by root and
# must not be writable by group or other.
#
# Rationale:
# A user able to write a keyring directory or key file can make APT trust an arbitrary
# repository, leading to arbitrary code execution as root on the next package install.
#
# @param enforce
#    Enforce the rule
#
# @param dir_mode
#    Mode of the keyring directories
#
# @param file_mode
#    Mode of the gpg key files
#
# @param directories
#    The keyring directories to manage
#
# @example
#   class { 'cis_security_hardening::rules::apt_keyring_perms':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::apt_keyring_perms (
  Boolean $enforce                         = false,
  Stdlib::Filemode $dir_mode               = '0755',
  Stdlib::Filemode $file_mode              = '0644',
  Array[Stdlib::Absolutepath] $directories = ['/etc/apt/trusted.gpg.d', '/usr/share/keyrings'],
) {
  if $enforce {
    $directories.each |Stdlib::Absolutepath $dir| {
      cis_security_hardening::recursive_file_permissions { $dir:
        file_mode => $file_mode,
        dir_mode  => $dir_mode,
        owner     => 'root',
        group     => 'root',
      }
    }
  }
}
