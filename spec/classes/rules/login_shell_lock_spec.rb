# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::login_shell_lock' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'cis_security_hardening' => {
              'accounts' => {
                'no_valid_shell_unlocked' => %w[svcaccount],
              },
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
            is_expected.to contain_exec('lock account without a valid login shell: svcaccount').
              with(
                'command' => 'usermod -L svcaccount',
                'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
                'onlyif'  => "passwd -S svcaccount | awk '{print $2}' | grep -qv '^L'"
              )
          else
            is_expected.not_to contain_exec('lock account without a valid login shell: svcaccount')
          end
        }
      end
    end

    context "on #{os} with enforce = true and an excluded account" do
      let(:facts) do
        os_facts.merge(
          'cis_security_hardening' => {
            'accounts' => {
              'no_valid_shell_unlocked' => %w[svcaccount otheraccount],
            },
          }
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'exclude' => ['otheraccount'],
        }
      end

      it {
        is_expected.to compile
        is_expected.to contain_exec('lock account without a valid login shell: svcaccount')
        is_expected.not_to contain_exec('lock account without a valid login shell: otheraccount')
      }
    end
  end
end
