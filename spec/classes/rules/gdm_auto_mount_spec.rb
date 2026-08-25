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
            # automount/automount-open (CIS 1.7.6/1.7.7) and autorun-never (CIS 1.7.8/1.7.9) are
            # independent controls, both enforced together regardless of OS -- regression: these
            # used to be mutually exclusive based on an os.name == 'debian' check that never
            # matched Ubuntu (os.name == 'Ubuntu'), so Ubuntu never got autorun-never and Debian
            # never got automount/automount-open.
            is_expected.to contain_dconf__db('media-automount').
              with(
                'db_dir'         => '/etc/dconf/db/local.d',
                'db_filename'    => '00-media-automount',
                'locks_filename' => '00-media-automount',
                'settings'       => {
                  'org/gnome/desktop/media-handling' => {
                    'automount'      => 'false',
                    'automount-open' => 'false',
                    'autorun-never'  => 'true',
                  },
                },
                # rubocop:disable Layout/HashAlignment
                'locks' => [
                  '/org/gnome/desktop/media-handling/automount',
                  '/org/gnome/desktop/media-handling/automount-open',
                  '/org/gnome/desktop/media-handling/autorun-never'
                ]
                # rubocop:enable Layout/HashAlignment
              )
          else
            is_expected.not_to contain_dconf__db('media-automount')
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
      is_expected.not_to contain_dconf__db('media-automount')
    end
  end
end
