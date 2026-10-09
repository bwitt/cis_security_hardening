# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::gnome_gdm' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            cis_security_hardening: {
              gnome_gdm_conf: false,
              gnome_gdm: true
            }
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
          }
        end

        it {
          is_expected.to compile

          if os_facts[:os]['name'].casecmp('centos').zero? || os_facts[:os]['name'].casecmp('redhat').zero? ||
             os_facts[:os]['name'].casecmp('almalinux').zero? || os_facts[:os]['name'].casecmp('rocky').zero?

            if enforce
              is_expected.to contain_dconf__profile('gdm').with(
                'entries' => {
                  'user' => {
                    'type'  => 'user',
                    'order' => 10,
                  },
                  'gdm' => {
                    'type'  => 'system',
                    'order' => 20,
                  },
                  '/usr/share/gdm/greeter-dconf-defaults' => {
                    'type'  => 'file',
                    'order' => 30,
                  },
                }
              )

              is_expected.to contain_cis_security_hardening__dconf_db_entry('01-banner-message').
                with(
                  'db'       => 'gdm',
                  'settings' => {
                    'org/gnome/login-screen' => {
                      'banner-message-enable' => 'true',
                      'banner-message-text'   => "'Authorized uses only. All activity may be monitored and reported.'",
                    },
                  },
                  'locks' => [ # rubocop:disable Layout/HashAlignment
                    '/org/gnome/login-screen/banner-message-enable',
                    '/org/gnome/login-screen/banner-message-text',
                  ]
                )

              is_expected.to contain_cis_security_hardening__dconf_db_entry('00-login-screen').
                with(
                  'db'       => 'gdm',
                  'settings' => {
                    'org/gnome/login-screen' => {
                      'disable-user-list' => 'true',
                    },
                  },
                  'locks' => [ # rubocop:disable Layout/HashAlignment
                    '/org/gnome/login-screen/disable-user-list',
                  ]
                )
            else
              is_expected.not_to contain_dconf__profile('gdm')
              is_expected.not_to contain_cis_security_hardening__dconf_db_entry('01-banner-message')
              is_expected.not_to contain_cis_security_hardening__dconf_db_entry('00-login-screen')
            end

            is_expected.not_to contain_file('/etc/gdm3/greeter.dconf-defaults')

          elsif os_facts[:os]['name'].casecmp('debian').zero?

            if enforce
              if os_facts[:os]['release']['major'] > '10'

                is_expected.to contain_dconf__profile('cis').
                  with(
                    'entries' => {
                      'user' => {
                        'type'  => 'user',
                        'order' => 10,
                      },
                      'cis' => {
                        'type'  => 'system',
                        'order' => 20,
                      },
                      '/usr/share/cis/greeter-dconf-defaults' => {
                        'type'  => 'file',
                        'order' => 30,
                      },
                    }
                  )

                is_expected.to contain_cis_security_hardening__dconf_db_entry('01-banner-message').
                  with(
                    'db'       => 'cis',
                    'settings' => {
                      'org/gnome/login-screen' => {
                        'banner-message-enable' => 'true',
                        'banner-message-text'   => "'Authorized uses only. All activity may be monitored and reported.'",
                        'disable-user-list'     => 'true',
                      },
                    },
                    'locks' => [ # rubocop:disable Layout/HashAlignment
                      '/org/gnome/login-screen/banner-message-enable',
                      '/org/gnome/login-screen/banner-message-text',
                      '/org/gnome/login-screen/disable-user-list',
                    ]
                  )

              else
                is_expected.to contain_file('/etc/gdm3/greeter.dconf-defaults').
                  with(
                    'ensure'  => 'file',
                    'content' => "[org/gnome/login-screen]\nbanner-message-enable=true\nbanner-message-text='Authorized uses only. All activity may be monitored and reported.'\ndisable-user-list=true\n",
                    'group'   => 'root',
                    'mode'    => '0644'
                  )
              end
            else
              is_expected.not_to contain_dconf__profile('cis')
              is_expected.not_to contain_cis_security_hardening__dconf_db_entry('01-banner-message')
              is_expected.not_to contain_file('/etc/gdm3/greeter.dconf-defaults')
            end

          elsif os_facts[:os]['name'].casecmp('ubuntu').zero?

            if enforce
              is_expected.to contain_file('/etc/gdm3/greeter.dconf-defaults').
                with(
                  'ensure'  => 'file',
                  'content' => "[org/gnome/login-screen]\nbanner-message-enable=true\nbanner-message-text='Authorized uses only. All activity may be monitored and reported.'\ndisable-user-list=true\n",
                  'owner'   => 'root',
                  'group'   => 'root',
                  'mode'    => '0644'
                )
            else
              is_expected.not_to contain_file('/etc/gdm3/greeter.dconf-defaults')
            end

          elsif os_facts[:os]['name'].casecmp('sles').zero?

            if enforce
              is_expected.to contain_dconf__profile('gdm').with(
                'entries' => {
                  'user' => {
                    'type'  => 'user',
                    'order' => 10,
                  },
                  'gdm' => {
                    'type'  => 'system',
                    'order' => 20,
                  },
                  '/usr/share/gdm/greeter-dconf-defaults' => {
                    'type'  => 'file',
                    'order' => 30,
                  },
                }
              )

              is_expected.to contain_cis_security_hardening__dconf_db_entry('01-banner-message').
                with(
                  'db'       => 'gdm',
                  'settings' => {
                    'org/gnome/login-screen' => {
                      'banner-message-enable' => 'true',
                      'banner-message-text'   => "'Authorized uses only. All activity may be monitored and reported.'",
                    },
                  },
                  'locks' => [ # rubocop:disable Layout/HashAlignment
                    '/org/gnome/login-screen/banner-message-enable',
                    '/org/gnome/login-screen/banner-message-text',
                  ]
                )

              is_expected.to contain_cis_security_hardening__dconf_db_entry('00-login-screen').
                with(
                  'db'       => 'gdm',
                  'settings' => {
                    'org/gnome/login-screen' => {
                      'disable-user-list' => 'true',
                    },
                  },
                  'locks' => [ # rubocop:disable Layout/HashAlignment
                    '/org/gnome/login-screen/disable-user-list',
                  ]
                )
            else
              is_expected.not_to contain_dconf__profile('gdm')
              is_expected.not_to contain_cis_security_hardening__dconf_db_entry('01-banner-message')
              is_expected.not_to contain_cis_security_hardening__dconf_db_entry('00-login-screen')
            end
          end
        }
      end
    end
  end
end
