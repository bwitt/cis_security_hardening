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
# removing a file a user may be relying on without warning them first is its own risk. Ownership
# on dotfiles under a home directory shared by more than one local interactive user is likewise
# alert-only rather than auto-corrected, since which user is "correct" is genuinely ambiguous.
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

    $shared = fact('cis_security_hardening.accounts.dot_file_status.dotfiles_shared')
    if $shared != undef and !empty($shared) {
      $shared.each | String $path | {
        notify { "dot file ownership ambiguous, home directory shared: ${path}":
          message  => "CIS: '${path}' is under a home directory shared by more than one local interactive user -- ownership cannot be auto-corrected since it's ambiguous which user is correct; investigate manually per local site policy",
          loglevel => 'warning',
        }
      }
    }

    $group_unresolvable = fact('cis_security_hardening.accounts.dot_file_status.dotfiles_group_unresolvable')
    if $group_unresolvable != undef and !empty($group_unresolvable) {
      $group_unresolvable.each | String $path | {
        notify { "dot file group ownership cannot be verified: ${path}":
          message  => "CIS: could not resolve the owning user's primary group for '${path}' (NSS lookup failure) -- group ownership cannot be auto-corrected without a known-good target; investigate manually per local site policy",
          loglevel => 'warning',
        }
      }
    }

    $strict_perm = fact('cis_security_hardening.accounts.dot_file_status.dotfiles_strict_perm')
    if $strict_perm != undef and !empty($strict_perm) {
      $strict_perm.each | String $path | {
        exec { "restrict dot file permissions: ${path}":
          command => "/bin/chmod u-x,go-rwx ${stdlib::shell_escape($path)}",
          onlyif  => "/usr/bin/test $(( 0$(/usr/bin/stat -c %a ${stdlib::shell_escape($path)}) & 0177 )) -gt 0",
        }
      }
    }

    $moderate_perm = fact('cis_security_hardening.accounts.dot_file_status.dotfiles_moderate_perm')
    if $moderate_perm != undef and !empty($moderate_perm) {
      $moderate_perm.each | String $path | {
        exec { "restrict dot file permissions: ${path}":
          command => "/bin/chmod u-x,go-wx ${stdlib::shell_escape($path)}",
          onlyif  => "/usr/bin/test $(( 0$(/usr/bin/stat -c %a ${stdlib::shell_escape($path)}) & 0133 )) -gt 0",
        }
      }
    }

    $wrong_owner = fact('cis_security_hardening.accounts.dot_file_status.dotfiles_wrong_owner')
    if $wrong_owner != undef and !empty($wrong_owner) {
      $wrong_owner.each | String $path, String $user | {
        exec { "correct dot file owner: ${path}":
          command => "/bin/chown ${stdlib::shell_escape($user)} ${stdlib::shell_escape($path)}",
          unless  => "/usr/bin/test \"$(/usr/bin/stat -c %U ${stdlib::shell_escape($path)})\" = ${stdlib::shell_escape($user)}",
        }
      }
    }

    $wrong_group = fact('cis_security_hardening.accounts.dot_file_status.dotfiles_wrong_group')
    if $wrong_group != undef and !empty($wrong_group) {
      $wrong_group.each | String $path, String $group | {
        exec { "correct dot file group: ${path}":
          command => "/bin/chgrp ${stdlib::shell_escape($group)} ${stdlib::shell_escape($path)}",
          unless  => "/usr/bin/test \"$(/usr/bin/stat -c %G ${stdlib::shell_escape($path)})\" = ${stdlib::shell_escape($group)}",
        }
      }
    }
  }
}
