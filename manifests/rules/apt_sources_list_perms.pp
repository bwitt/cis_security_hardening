# @summary
#    Ensure access to the /etc/apt/sources.list.d directory is configured
#
# /etc/apt/sources.list.d defines the repositories APT downloads packages from. The directory
# and the files in it must be owned by root and must not be writable by group or other.
#
# Rationale:
# A user able to write a file here can add a repository of their choosing, which combined
# with a key they control gives arbitrary code execution as root on the next upgrade.
#
# @param enforce
#    Enforce the rule
#
# @param dir_mode
#    Mode of the /etc/apt/sources.list.d directory
#
# @param file_mode
#    Mode of the repository definition files
#
# @example
#   class { 'cis_security_hardening::rules::apt_sources_list_perms':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::apt_sources_list_perms (
  Boolean $enforce            = false,
  Stdlib::Filemode $dir_mode  = '0755',
  Stdlib::Filemode $file_mode = '0644',
) {
  if $enforce {
    cis_security_hardening::recursive_file_permissions { '/etc/apt/sources.list.d':
      file_mode => $file_mode,
      dir_mode  => $dir_mode,
      owner     => 'root',
      group     => 'root',
    }
  }
}
