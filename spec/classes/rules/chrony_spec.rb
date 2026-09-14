# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::chrony' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os}" do
        describe "without ntp servers defined, enforce = #{enforce}" do
          let(:facts) { os_facts }
          let(:params) do
            {
              'enforce' => enforce,
              'makestep_seconds' => 1,
              'makestep_updates' => -1,
            }
          end

          it {
            is_expected.to compile

            if enforce
              is_expected.to contain_class('chrony').
                with(
                  'makestep_seconds' => 1,
                  'makestep_updates' => -1
                )

              if os_facts[:os]['name'].casecmp('ubuntu').zero?
                is_expected.to contain_package('ntp').
                  with(
                    'ensure' => 'purged'
                  )
                is_expected.to contain_service('systemd-timesyncd').
                  with(
                    'ensure' => 'stopped',
                    'enable' => false
                  )
              end

              if os_facts[:os]['family'].casecmp('redhat').zero?
                options = os_facts[:os]['release']['major'].to_i >= 9 ? '-F 2 -u chrony' : '-u chrony'
                is_expected.to contain_class('chrony').
                  with(
                    'options' => options
                  )
                is_expected.to contain_file('/etc/sysconfig/chronyd').
                  with_content(%r{^OPTIONS="#{Regexp.escape(options)}"$})
              end
            else
              is_expected.not_to contain_class('chrony')
              is_expected.not_to contain_package('ntp')
              is_expected.not_to contain_service('systemd-timesyncd')
              is_expected.not_to contain_file('/etc/sysconfig/chronyd')
            end
          }
        end

        describe "with ntp servers defined, enforce = #{enforce}" do
          let(:facts) { os_facts }
          let(:params) do
            {
              'enforce' => enforce,
              'ntp_servers' => {
                '10.10.10.1' => ['iburst', 'maxpoll 17'],
                '10.10.10.2' => ['iburst', 'maxpoll 17'],
              },
              'makestep_seconds' => 1,
              'makestep_updates' => -1,
            }
          end

          it {
            is_expected.to compile

            if enforce
              is_expected.to contain_class('chrony').
                with(
                  'servers' => {
                    '10.10.10.1' => ['iburst', 'maxpoll 17'],
                    '10.10.10.2' => ['iburst', 'maxpoll 17'],
                  },
                  'makestep_seconds' => 1,
                  'makestep_updates' => -1
                )

              if os_facts[:os]['name'].casecmp('ubuntu').zero?
                is_expected.to contain_package('ntp').
                  with(
                    'ensure' => 'purged'
                  )
                is_expected.to contain_service('systemd-timesyncd').
                  with(
                    'ensure' => 'stopped',
                    'enable' => false
                  )
              end

              if os_facts[:os]['family'].casecmp('redhat').zero?
                options = os_facts[:os]['release']['major'].to_i >= 9 ? '-F 2 -u chrony' : '-u chrony'
                is_expected.to contain_class('chrony').
                  with(
                    'options' => options
                  )
                is_expected.to contain_file('/etc/sysconfig/chronyd').
                  with_content(%r{^OPTIONS="#{Regexp.escape(options)}"$})
              end
            else
              is_expected.not_to contain_class('chrony')
              is_expected.not_to contain_package('ntp')
              is_expected.not_to contain_service('systemd-timesyncd')
              is_expected.not_to contain_file('/etc/sysconfig/chronyd')
            end
          }
        end
      end
    end
  end
end
