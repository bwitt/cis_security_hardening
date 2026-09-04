# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]
removal_modes = %w[tag line]

describe 'cis_security_hardening::rules::sudo_require_password' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      removal_modes.each do |mode|
        context "on #{os} with enforce = #{enforce} and removal_mode = #{mode}" do
          let(:facts) { os_facts }
          let(:params) do
            {
              'enforce' => enforce,
              'removal_mode' => mode,
            }
          end

          it {
            is_expected.to compile

            if enforce
              is_expected.to contain_exec('cis sudo require password').
                with(
                  'onlyif'   => "grep -Eqrs '^[[:space:]]*[^#].*NOPASSWD[[:space:]]*:' /etc/sudoers /etc/sudoers.d",
                  'provider' => 'shell'
                )
              cmd = catalogue.resource('Exec[cis sudo require password]')[:command]
              # sudoers.d fragments must be processed before the main file
              expect(cmd).to include('for f in /etc/sudoers.d/* /etc/sudoers; do')
              # each file is validated on its own and reverted individually
              expect(cmd).to include('visudo -c -f "$f"')
              expect(cmd).to include('mv -f -- "$f.cis-bak" "$f"')
              # comments must never be rewritten
              expect(cmd).to include('/^[[:space:]]*#/!s') if mode == 'tag'
              expect(cmd).to include("sed -ri '/^[[:space:]]*[^#].*NOPASSWD[[:space:]]*:/d'") if mode == 'line'
            else
              is_expected.not_to contain_exec('cis sudo require password')
            end
          }
        end
      end
    end
  end
end
