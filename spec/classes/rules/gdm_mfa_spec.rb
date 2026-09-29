# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::gdm_mfa' do
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
          }
        end

        it {
          is_expected.to compile

          if enforce
            is_expected.to contain_cis_security_hardening__dconf_db_entry('06-mfa').
              with(
                'db' => 'local',
                'settings' => {
                  'org/gnome/login-screen' => {
                    'enable-smartcard-authentication' => 'true',
                  },
                },
                'locks' => [
                  '/org/gnome/login-screen/enable-smartcard-authentication'
                ]
              )
          else
            is_expected.not_to contain_cis_security_hardening__dconf_db_entry('06-mfa')
          end
        }
      end
    end
  end
end
