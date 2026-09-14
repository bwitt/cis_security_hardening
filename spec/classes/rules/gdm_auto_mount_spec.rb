# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::gdm_auto_mount' do
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
            is_expected.to contain_cis_security_hardening__dconf_db_entry('00-media-automount').
              with(
                'db' => 'local',
                'settings' => {
                  'org/gnome/desktop/media-handling' => {
                    'automount'      => 'false',
                    'automount-open' => 'false',
                    'autorun-never'  => 'true',
                  },
                }
              ).with_locks(
                [
                  '/org/gnome/desktop/media-handling/automount',
                  '/org/gnome/desktop/media-handling/automount-open',
                  '/org/gnome/desktop/media-handling/autorun-never',
                ]
              )
          else
            is_expected.not_to contain_cis_security_hardening__dconf_db_entry('00-media-automount')
          end
        }
      end
    end
  end

  context 'when the gnome_gdm fact is absent' do
    let(:facts) { on_supported_os.first[1] }
    let(:params) { { 'enforce' => true } }

    it 'compiles cleanly with no resources declared' do
      is_expected.to compile
      is_expected.not_to contain_cis_security_hardening__dconf_db_entry('00-media-automount')
    end
  end
end
