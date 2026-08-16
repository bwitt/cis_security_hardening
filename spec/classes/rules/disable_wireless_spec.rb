# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::disable_wireless' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce} without nmcli" do
        let(:facts) do
          os_facts.merge(
            'cis_security_hardening' => {
              'wlan_interfaces_count' => 1,
              'wlan_interfaces' => ['wlp3s0'],
              'wlan_modules' => ['iwlwifi'],
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
            is_expected.to contain_kmod__blacklist('iwlwifi')
            is_expected.to contain_kmod__install('iwlwifi').with('command' => '/bin/false')

            is_expected.to contain_exec('shutdown wlan interface wlp3s0').
              with(
                'command' => 'ip link set wlp3s0 down',
                'path'    => ['/bin', '/sbin', '/usr/bin', '/usr/sbin'],
                'onlyif'  => "ip link show wlp3s0 | grep 'state UP'"
              )
          else
            is_expected.not_to contain_kmod__blacklist('iwlwifi')
            is_expected.not_to contain_exec('shutdown wlan interface wlp3s0')
          end
        }
      end

      context "on #{os} with enforce = #{enforce} with nmcli" do
        let(:facts) do
          os_facts.merge(
            'cis_security_hardening' => {
              'wlan_status' => 'enabled',
              'wlan_modules' => ['iwlwifi'],
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
            is_expected.to contain_exec('switch radio off').
              with(
                'command' => 'nmcli radio all off',
                'path'    => ['/bin', '/sbin', '/usr/bin', '/usr/sbin']
              )

            # the modules are blocked even where the radio can be turned off now
            is_expected.to contain_kmod__blacklist('iwlwifi')
            is_expected.to contain_kmod__install('iwlwifi')
          else
            is_expected.not_to contain_exec('switch radio off')
            is_expected.not_to contain_kmod__install('iwlwifi')
          end
        }
      end

      context "on #{os} with enforce = #{enforce} and no wireless hardware" do
        let(:facts) do
          os_facts.merge(
            'cis_security_hardening' => {
              'wlan_interfaces_count' => 0,
              'wlan_interfaces' => [],
              'wlan_modules' => [],
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
          is_expected.not_to contain_exec('switch radio off')
        }
      end
    end
  end
end
