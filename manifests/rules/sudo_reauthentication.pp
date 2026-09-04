# @summary
#    Ensure re-authentication for privilege escalation is not disabled globally
#
# The !authenticate tag disables the password prompt for the rules it applies to. This rule
# removes those tags from /etc/sudoers and /etc/sudoers.d. A line reduced to nothing but a
# Defaults keyword is not valid sudoers syntax and is removed as well.
#
# Rationale:
# Disabling re-authentication means privilege escalation never requires proof that the
# person at the keyboard is the account owner.
#
# Note: /etc/sudoers.d is processed before /etc/sudoers, because validating the main file
# follows its @includedir and would otherwise still see the unfixed fragments. Each file is
# backed up, validated with visudo -c -f, and reverted on its own if validation fails.
#
# @param enforce
#    Enforce the rule
#
# @param sudoers_file
#    The main sudoers file
#
# @param sudoers_dir
#    The sudoers include directory
#
# @example
#   class { 'cis_security_hardening::rules::sudo_reauthentication':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::sudo_reauthentication (
  Boolean $enforce                   = false,
  Stdlib::Absolutepath $sudoers_file = '/etc/sudoers',
  Stdlib::Absolutepath $sudoers_dir  = '/etc/sudoers.d',
) {
  if $enforce {
    $detect = '^[[:space:]]*[^#].*![[:space:]]*authenticate'

    $script = @("SCRIPT"/$L)
      rc=0
      for f in ${sudoers_dir}/* ${sudoers_file}; do
        [ -f "\$f" ] || continue
        grep -Eq '${detect}' "\$f" || continue
        cp -p -- "\$f" "\$f.cis-bak"
        sed -ri '/^[[:space:]]*#/!s/[[:space:]]*![[:space:]]*authenticate//g' -- "\$f"
        sed -ri '/^[[:space:]]*Defaults[^[:space:]]*[[:space:]]*\$/d' -- "\$f"
        if visudo -c -f "\$f" >/dev/null 2>&1; then
          rm -f -- "\$f.cis-bak"
        else
          mv -f -- "\$f.cis-bak" "\$f"
          echo "CIS 5.2.5: \$f failed visudo validation, reverted" >&2
          rc=1
        fi
      done
      exit \$rc
      | SCRIPT

    exec { 'cis sudo reauthentication':
      command  => $script,
      path     => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      onlyif   => "grep -Eqrs '${detect}' ${sudoers_file} ${sudoers_dir}",
      provider => shell,
    }
  }
}
