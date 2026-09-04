# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]
uninstall_options = [true, false]

describe 'cis_security_hardening::rules::nfs' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      uninstall_options.each do |uninstall|
        context "on #{os} with enforce = #{enforce} and uninstall = #{uninstall}" do
          let(:facts) { os_facts }
          let(:params) do
            {
              'enforce' => enforce,
              'uninstall' => uninstall,
            }
          end

          family = os_facts[:os]['family'].downcase

          it {
            is_expected.to compile

            if enforce && uninstall
              case family
              when 'redhat'
                is_expected.to contain_package('nfs-utils').with('ensure' => 'absent')
                is_expected.not_to contain_package('nfs-kernel-server')
              when 'suse'
                is_expected.to contain_package('nfs-utils').with('ensure' => 'absent')
                is_expected.to contain_package('nfs-kernel-server').with('ensure' => 'absent')
              else
                is_expected.to contain_package('nfs-kernel-server').with('ensure' => 'purged')
                is_expected.not_to contain_package('nfs-utils')
              end

              # removing the package stops the service itself; nothing else is managed
              is_expected.not_to contain_service('nfs-server')
              is_expected.not_to contain_exec('mask nfs-server service')

            elsif enforce && !uninstall
              is_expected.to contain_service('nfs-server').
                with(
                  'ensure' => 'stopped',
                  'enable' => false
                )
              is_expected.to contain_exec('mask nfs-server service').
                with(
                  'command' => 'systemctl --now mask nfs-server',
                  'path'    => ['/usr/bin', '/bin'],
                  'unless'  => 'test "$(systemctl is-enabled nfs-server)" = "masked"'
                )
              is_expected.not_to contain_package('nfs-utils')
              is_expected.not_to contain_package('nfs-kernel-server')

            else
              is_expected.not_to contain_package('nfs-utils')
              is_expected.not_to contain_package('nfs-kernel-server')
              is_expected.not_to contain_service('nfs-server')
              is_expected.not_to contain_exec('mask nfs-server service')
            end

            # 'nfs' was never a valid unit name on any supported release
            is_expected.not_to contain_service('nfs')
          }
        end
      end
    end
  end
end
