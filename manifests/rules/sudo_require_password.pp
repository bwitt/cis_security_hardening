# @summary
#    Ensure users must provide password for escalation
#
# A NOPASSWD tag lets the listed users run the listed commands without re-entering their
# password. This rule removes those tags from /etc/sudoers and /etc/sudoers.d.
#
# Rationale:
# Passwordless escalation means anyone who obtains a user's session immediately gains that
# user's full sudo rights without knowing the user's password.
#
# Note: /etc/sudoers.d is processed before /etc/sudoers, because validating the main file
# follows its @includedir and would otherwise still see the unfixed fragments. Each file is
# backed up, validated with visudo -c -f, and reverted on its own if validation fails.
#
# @param enforce
#    Enforce the rule
#
# @param removal_mode
#    Remove only the NOPASSWD tag and keep the grant, or remove the whole rule
#
# @param sudoers_file
#    The main sudoers file
#
# @param sudoers_dir
#    The sudoers include directory
#
# @example
#   class { 'cis_security_hardening::rules::sudo_require_password':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::sudo_require_password (
  Boolean $enforce                   = false,
  Enum['tag', 'line'] $removal_mode  = 'tag',
  Stdlib::Absolutepath $sudoers_file = '/etc/sudoers',
  Stdlib::Absolutepath $sudoers_dir  = '/etc/sudoers.d',
) {
  if $enforce {
    $detect = '^[[:space:]]*[^#].*NOPASSWD[[:space:]]*:'

    $edit = $removal_mode ? {
      'line'  => "sed -ri '/${detect}/d'",
      default => "sed -ri '/^[[:space:]]*#/!s/[[:space:]]*NOPASSWD[[:space:]]*:[[:space:]]*/ /g'",
    }

    $script = @("SCRIPT"/$L)
      rc=0
      for f in ${sudoers_dir}/* ${sudoers_file}; do
        [ -f "\$f" ] || continue
        grep -Eq '${detect}' "\$f" || continue
        cp -p -- "\$f" "\$f.cis-bak"
        ${edit} -- "\$f"
        if visudo -c -f "\$f" >/dev/null 2>&1; then
          rm -f -- "\$f.cis-bak"
        else
          mv -f -- "\$f.cis-bak" "\$f"
          echo "CIS 5.2.4: \$f failed visudo validation, reverted" >&2
          rc=1
        fi
      done
      exit \$rc
      | SCRIPT

    exec { 'cis sudo require password':
      command  => $script,
      path     => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      onlyif   => "grep -Eqrs '${detect}' ${sudoers_file} ${sudoers_dir}",
      provider => shell,
    }
  }
}
