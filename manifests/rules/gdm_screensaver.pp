# @summary
#    Ensure GNOME Screensaver period of inactivity is configured
#
# The operating system must initiate a screensaver after a 15-minute period of inactivity for graphical user interfaces.
#
# Rationale:
# A session time-out lock with the screensaver is a temporary action taken when a user stops work and moves away from the
# immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence.
# Rather than relying on the user to manually lock their operating system session prior to vacating the vicinity, operating
# systems need to be able to identify when a user's session has idled and take action to initiate the session lock.
#
# The screensaver is implemented at the point where session activity can be determined and/or controlled.
#
# @param enforce
#    Enforce the rule.
# @param timeout
#    The idle time.
#
#
# @example
#   class { 'cis_security_hardening::rules::gdm_screensaver':
#     enforce => true,
#     timeout => 900,
#   }
#
# @api private
class cis_security_hardening::rules::gdm_screensaver (
  Boolean $enforce   = false,
  Integer $timeout   = 900,
) {
  $gnome_gdm = fact('cis_security_hardening.gnome_gdm')
  if $enforce and $gnome_gdm != undef and $gnome_gdm {
    include dconf
    dconf::db { 'screensaver-timeout':
      db_dir         => '/etc/dconf/db/local.d',
      db_filename    => '03-screensaver-timeout',
      locks_filename => '03-screensaver-timeout',
      settings       => {
        'org/gnome/desktop/session' => {
          'idle-delay'              => "uint32 ${timeout}",
        },
      },
      locks          => [
        '/org/gnome/desktop/session/idle-delay',
      ],
    }
  }
}
