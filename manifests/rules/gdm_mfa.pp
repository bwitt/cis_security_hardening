# @summary
#    Ensure users must authenticate users using MFA via a graphical user logon
#
# The operating system must uniquely identify and must authenticate users using multifactor authentication
# via a graphical user logon.
#
# Rationale:
# To assure accountability and prevent unauthenticated access, users must be identified and authenticated to
# prevent potential misuse and compromise of the system.
#
# Multifactor solutions that require devices separate from information systems gaining access include, for example,
# hardware tokens providing time-based or challenge-response authenticators and smart cards such as the U.S.
# Government Personal Identity Verification card and the DoD Common Access Card.
#
# Satisfies: SRG-OS-000375-GPOS-00161,SRG-OS-000375-GPOS-00162
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::gdm_mfa':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::gdm_mfa (
  Boolean $enforce = false,
) {
  $gnome_gdm = fact('cis_security_hardening.gnome_gdm')
  if  $enforce and $gnome_gdm != undef and $gnome_gdm {
    include dconf
    cis_security_hardening::dconf_db_entry { '06-mfa':
      db       => 'local',
      settings => {
        'org/gnome/login-screen' => {
          'enable-smartcard-authentication' => 'true',
        },
      },
      locks    => [
        '/org/gnome/login-screen/enable-smartcard-authentication',
      ],
    }
  }
}
