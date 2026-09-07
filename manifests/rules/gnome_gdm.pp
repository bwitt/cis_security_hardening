# @summary
#    Ensure GDM login banner is configured
#
# GDM is the GNOME Display Manager which handles graphical login for GNOME based systems.
#
# Rationale:
# Warning messages inform users who are attempting to login to the system of their legal
# status regarding the system and must include the name of the organization that owns the
# system and any monitoring policies that are in place.

# @param enforce
#    Enforce the rule
# @param banner_message
#    The banner message.
#
# @example
#   class { 'cis_security_hardening::rules::gnome_gdm':
#       enforce => true,
#   }
#
# @example
#   include cis_security_hardening::rules::gnome_gdm
#
# @api private
class cis_security_hardening::rules::gnome_gdm (
  Boolean $enforce = false,
  String $banner_message = 'Authorized uses only. All activity may be monitored and reported.',
) {
  $gnome_gdm = fact('cis_security_hardening.gnome_gdm')
  if $enforce and $gnome_gdm != undef and $gnome_gdm {
    include dconf
    case $facts['os']['name'].downcase() {
      'redhat', 'centos', 'almalinux', 'rocky': {
        dconf::profile { 'gdm':
          entries => {
            'user'                                  => {
              'type'  => 'user',
              'order' => 10,
            },
            'gdm'                                   => {
              'type'  => 'system',
              'order' => 20,
            },
            '/usr/share/gdm/greeter-dconf-defaults' => {
              'type'  => 'file',
              'order' => 30,
            },
          },
        }

        cis_security_hardening::dconf_db_entry { '01-banner-message':
          db       => 'gdm',
          settings => {
            'org/gnome/login-screen' => {
              'banner-message-enable' => 'true',
              'banner-message-text'   => "'${banner_message}'",
            },
          },
          locks    => [
            '/org/gnome/login-screen/banner-message-enable',
            '/org/gnome/login-screen/banner-message-text',
          ],
        }

        cis_security_hardening::dconf_db_entry { '00-login-screen':
          db       => 'gdm',
          settings => {
            'org/gnome/login-screen' => {
              'disable-user-list' => 'true',
            },
          },
          locks    => [
            '/org/gnome/login-screen/disable-user-list',
          ],
        }
      }
      'debian': {
        if $facts['os']['release']['major'] > '10' {
          dconf::profile { 'cis':
            entries => {
              'user'                                  => {
                'type'  => 'user',
                'order' => 10,
              },
              'cis'                                   => {
                'type'  => 'system',
                'order' => 20,
              },
              '/usr/share/cis/greeter-dconf-defaults' => {
                'type'  => 'file',
                'order' => 30,
              },
            },
          }

          cis_security_hardening::dconf_db_entry { '01-banner-message':
            db       => 'cis',
            settings => {
              'org/gnome/login-screen' => {
                'banner-message-enable' => 'true',
                'banner-message-text'   => "'${banner_message}'",
                'disable-user-list'     => 'true',
              },
            },
            locks    => [
              '/org/gnome/login-screen/banner-message-enable',
              '/org/gnome/login-screen/banner-message-text',
              '/org/gnome/login-screen/disable-user-list',
            ],
          }
        } else {
          file { '/etc/gdm3/greeter.dconf-defaults':
            ensure  => file,
            content => "[org/gnome/login-screen]\nbanner-message-enable=true\nbanner-message-text='${banner_message}'\ndisable-user-list=true\n",
            owner   => 'root',
            group   => 'root',
            mode    => '0644',
          }
        }
      }
      'ubuntu': {
        file { '/etc/gdm3/greeter.dconf-defaults':
          ensure  => file,
          content => "[org/gnome/login-screen]\nbanner-message-enable=true\nbanner-message-text='${banner_message}'\ndisable-user-list=true\n",
          owner   => 'root',
          group   => 'root',
          mode    => '0644',
        }
      }
      'sles': {
        dconf::profile { 'gdm':
          entries => {
            'user'                                  => {
              'type'  => 'user',
              'order' => 10,
            },
            'gdm'                                   => {
              'type'  => 'system',
              'order' => 20,
            },
            '/usr/share/gdm/greeter-dconf-defaults' => {
              'type'  => 'file',
              'order' => 30,
            },
          },
        }

        cis_security_hardening::dconf_db_entry { '01-banner-message':
          db       => 'gdm',
          settings => {
            'org/gnome/login-screen' => {
              'banner-message-enable' => 'true',
              'banner-message-text'   => "'${banner_message}'",
            },
          },
          locks    => [
            '/org/gnome/login-screen/banner-message-enable',
            '/org/gnome/login-screen/banner-message-text',
          ],
        }

        cis_security_hardening::dconf_db_entry { '00-login-screen':
          db       => 'gdm',
          settings => {
            'org/gnome/login-screen' => {
              'disable-user-list' => 'true',
            },
          },
          locks    => [
            '/org/gnome/login-screen/disable-user-list',
          ],
        }
      }
      default: {
        # nothing to do yet
      }
    }
  }
}
