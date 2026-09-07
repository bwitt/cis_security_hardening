# @summary
#    Ensure the graphical user Ctrl-Alt-Delete key sequence is disabled
#
# The operating system must disable the x86 Ctrl-Alt-Delete key sequence if a graphical user interface is installed.
#
# Rationale:
# A locally logged-on user who presses Ctrl-Alt-Delete, when at the console, can reboot the system. If accidentally
# pressed, as could happen in the case of a mixed OS environment, this can create the risk of short-term loss of
# availability of systems due to unintentional reboot. In the graphical environment, risk of unintentional reboot
# from the Ctrl-Alt-Delete sequence is reduced because the user will be prompted before any action is taken.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::ctrl_alt_del_graphical':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::ctrl_alt_del_graphical (
  Boolean $enforce = false
) {
  $gnome_gdm = fact('cis_security_hardening.gnome_gdm')
  if  $enforce and $gnome_gdm != undef and $gnome_gdm {
    include dconf
    dconf::db { 'disable-cad':
      db_dir         => '/etc/dconf/db/local.d',
      db_filename    => '00-disable-CAD',
      locks_filename => '00-disable-CAD',
      settings       => {
        'org/gnome/settings-daemon/plugins/media-keys' => {
          'logout' => '',
        },
      },
      locks          => [
        '/org/gnome/settings-daemon/plugins/media-keys/logout',
      ],
    }
  }
}
