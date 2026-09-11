# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::sudo_reauthentication' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) { os_facts }
        let(:params) do
          {
            'enforce' => enforce,
          }
        end

        it {
          is_expected.to compile

          if enforce
            is_expected.to contain_exec('cis sudo reauthentication').
              with(
                'onlyif'   => "grep -Eqrs '^[[:space:]]*[^#].*![[:space:]]*authenticate' /etc/sudoers /etc/sudoers.d",
                'provider' => 'shell'
              )
            cmd = catalogue.resource('Exec[cis sudo reauthentication]')[:command]
            expect(cmd).to include('for f in /etc/sudoers.d/* /etc/sudoers; do')
            expect(cmd).to include('visudo -c -f "$f"')
            expect(cmd).to include('mv -f -- "$f.cis-bak" "$f"')
            # comments must never be rewritten
            expect(cmd).to include("sed -ri '/^[[:space:]]*#/!s/[[:space:]]*![[:space:]]*authenticate//g'")
            # a line reduced to a bare Defaults keyword is not valid sudoers and is removed
            expect(cmd).to include("sed -ri '/^[[:space:]]*Defaults[^[:space:]]*[[:space:]]*$/d'")
          else
            is_expected.not_to contain_exec('cis sudo reauthentication')
          end
        }
      end
    end
  end
end
