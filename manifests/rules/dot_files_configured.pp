# @summary
#    Ensure local interactive user dot files access is configured
#
# While the system administrator can establish secure permissions for users' "dot" files, users
# can easily override these. Of particular concern:
# - .forward - forwards a user's mail to another address
# - .rhosts - the "remote authentication" database for rcp/rlogin/rsh, bypassing standard
#   password-based authentication
# - .netrc - contains credentials for logging into a remote host or API
# - .bash_history - keeps track of the user's commands
#
# Rationale:
# User configuration files with excessive or incorrect access may enable malicious users to steal
# or modify other users' data or to gain another user's system privileges.
#
# Note: .forward and .rhosts are alert-only, not automatically deleted -- CIS's own remediation
# for these is "list ... to be investigated and manually deleted," not an automatic action, since
# removing a file a user may be relying on without warning them first is its own risk.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::dot_files_configured':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::dot_files_configured (
  Boolean $enforce = false,
) {
  if $enforce {
    $alert_only = fact('cis_security_hardening.accounts.dot_file_status.dotfiles_alert_only')
    if $alert_only != undef and !empty($alert_only) {
      $alert_only.each | String $path | {
        notify { "dot file flagged for manual review: ${path}":
          message  => "CIS: '${path}' exists -- investigate and delete manually per local site policy",
          loglevel => 'warning',
        }
      }
    }

    $strict_perm = fact('cis_security_hardening.accounts.dot_file_status.dotfiles_strict_perm')
    if $strict_perm != undef and !empty($strict_perm) {
      $strict_perm.each | String $path | {
        exec { "restrict dot file permissions: ${path}":
          command => "/bin/chmod u-x,go-rwx ${path}",
          onlyif  => "/usr/bin/test $(( 0$(/usr/bin/stat -c %a ${path}) & 0177 )) -gt 0",
        }
      }
    }

    $moderate_perm = fact('cis_security_hardening.accounts.dot_file_status.dotfiles_moderate_perm')
    if $moderate_perm != undef and !empty($moderate_perm) {
      $moderate_perm.each | String $path | {
        exec { "restrict dot file permissions: ${path}":
          command => "/bin/chmod u-x,go-wx ${path}",
          onlyif  => "/usr/bin/test $(( 0$(/usr/bin/stat -c %a ${path}) & 0133 )) -gt 0",
        }
      }
    }

    $wrong_owner = fact('cis_security_hardening.accounts.dot_file_status.dotfiles_wrong_owner')
    if $wrong_owner != undef and !empty($wrong_owner) {
      $wrong_owner.each | String $path, String $user | {
        exec { "correct dot file owner: ${path}":
          command => "/bin/chown ${user} ${path}",
          unless  => "/usr/bin/test \"$(/usr/bin/stat -c %U ${path})\" = \"${user}\"",
        }
      }
    }

    $wrong_group = fact('cis_security_hardening.accounts.dot_file_status.dotfiles_wrong_group')
    if $wrong_group != undef and !empty($wrong_group) {
      $wrong_group.each | String $path, String $group | {
        exec { "correct dot file group: ${path}":
          command => "/bin/chgrp ${group} ${path}",
          unless  => "/usr/bin/test \"$(/usr/bin/stat -c %G ${path})\" = \"${group}\"",
        }
      }
    }
  }
}
