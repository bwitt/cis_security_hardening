# @summary
#    Ensure local interactive user home directories are configured
#
# The user home directory is space defined for the particular user to set local environment
# variables and to store personal files. Since the user is accountable for files stored in the
# user home directory, the user must be the owner of the directory. Group or world-writable user
# home directories may enable malicious users to steal or modify other users' data or to gain
# another user's system privileges.
#
# Rationale:
# If the user's home directory does not exist, the user will be placed in "/" and will not be
# able to write any files or have local environment variables set.
#
# Note: this class only alerts on a missing home directory rather than creating one or altering
# the account -- CIS's own remediation is "lock the account / remove the user / create the
# directory per local site policy," none of which is a safe default to pick automatically.
# Ownership and permission drift on an *existing* home directory is corrected directly, since
# that has a single unambiguous safe fix.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::home_dirs_configured':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::home_dirs_configured (
  Boolean $enforce = false,
) {
  if $enforce {
    $missing = fact('cis_security_hardening.accounts.home_dir_status.missing_home_dir')
    if $missing != undef and !empty($missing) {
      $missing.each | String $user | {
        notify { "local interactive user has no home directory: ${user}":
          message  => "CIS: local interactive user '${user}' has no home directory",
          loglevel => 'warning',
        }
      }
    }

    $wrong_owner = fact('cis_security_hardening.accounts.home_dir_status.home_dir_wrong_owner')
    if $wrong_owner != undef and !empty($wrong_owner) {
      $wrong_owner.each | String $home, String $user | {
        exec { "correct home directory owner: ${home}":
          command => "/bin/chown ${user} ${home}",
          unless  => "/usr/bin/test \"$(/usr/bin/stat -c %U ${home})\" = \"${user}\"",
        }
      }
    }

    $excess_perms = fact('cis_security_hardening.accounts.home_dir_status.home_dir_excess_perms')
    if $excess_perms != undef and !empty($excess_perms) {
      $excess_perms.each | String $home | {
        exec { "remove excess home directory permissions: ${home}":
          command => "/bin/chmod g-w,o-rwx ${home}",
          onlyif  => "/usr/bin/test $(( 0$(/usr/bin/stat -c %a ${home}) & 027 )) -gt 0",
        }
      }
    }
  }
}
