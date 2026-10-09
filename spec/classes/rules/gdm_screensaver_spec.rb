# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::gdm_screensaver' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            cis_security_hardening: {
              gnome_gdm_conf: false,
              gnome_gdm: true,
            }
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'timeout' => 800,
          }
        end

        it {
          is_expected.to compile

          if enforce
            is_expected.to contain_cis_security_hardening__dconf_db_entry('03-screensaver-timeout').
              with(
                'db' => 'local',
                'settings' => {
                  'org/gnome/desktop/session' => {
                    'idle-delay' => 'uint32 800',
                  },
                },
                'locks' => [
                  '/org/gnome/desktop/session/idle-delay'
                ]
              )
          else
            is_expected.not_to contain_cis_security_hardening__dconf_db_entry('03-screensaver-timeout')
          end
        }
      end
    end
  end
end
