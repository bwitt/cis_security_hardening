# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::shadow_password_empty' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'cis_security_hardening' => {
              'accounts' => {
                'empty_password' => %w[test1 test2],
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
            is_expected.to contain_exec('lock account with empty password: test1').
              with(
                'command' => 'passwd -l test1',
                'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin']
              )
            is_expected.to contain_exec('lock account with empty password: test2').
              with(
                'command' => 'passwd -l test2',
                'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin']
              )
          else
            is_expected.not_to contain_exec('lock account with empty password: test1')
            is_expected.not_to contain_exec('lock account with empty password: test2')
          end
        }
      end
    end

    context "on #{os} with enforce = true and an excluded account" do
      let(:facts) do
        os_facts.merge(
          'cis_security_hardening' => {
            'accounts' => {
              'empty_password' => %w[test1 test2],
            },
          }
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'exclude' => ['test2'],
        }
      end

      it {
        is_expected.to compile
        is_expected.to contain_exec('lock account with empty password: test1')
        is_expected.not_to contain_exec('lock account with empty password: test2')
      }
    end
  end
end
