# @summary
#    Ensure access to the /etc/apt/auth.conf.d directory is configured
#
# /etc/apt/auth.conf.d holds the credentials APT uses for private repositories. The directory
# must be owned by root and the credential files must not be readable by other.
#
# Rationale:
# These files contain repository credentials in cleartext. Read access by any other account
# discloses them, and write access permits redirection of package downloads.
#
# @param enforce
#    Enforce the rule
#
# @param dir_mode
#    Mode of the /etc/apt/auth.conf.d directory
#
# @param file_mode
#    Mode of the credential files
#
# @example
#   class { 'cis_security_hardening::rules::apt_auth_conf_perms':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::apt_auth_conf_perms (
  Boolean $enforce            = false,
  Stdlib::Filemode $dir_mode  = '0755',
  Stdlib::Filemode $file_mode = '0640',
) {
  if $enforce {
    recursive_file_permissions { '/etc/apt/auth.conf.d':
      file_mode => $file_mode,
      dir_mode  => $dir_mode,
      owner     => 'root',
      group     => 'root',
    }
  }
}
