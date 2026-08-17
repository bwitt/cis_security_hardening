# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::tmp_filesystem' do
  let(:pre_condition) do
    <<-EOF
    exec { 'systemd-daemon-reload':
      command     => 'systemctl daemon-reload',
      path        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      refreshonly => true,
    }
    EOF
  end

  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) { os_facts }
        let(:params) do
          {
            'enforce' => enforce,
            'size'    => 2,
            'enable'  => false,
          }
        end

        it {
          is_expected.to compile

          filename = '/etc/systemd/system/tmp.mount'

          if enforce
            unless os_facts[:os]['name'].casecmp('redhat').zero? && os_facts[:os]['release']['major'] > '7'
              is_expected.to contain_file(filename).
                with(
                  'ensure' => 'file',
                  'owner' => 'root',
                  'group' => 'root',
                  'mode' => '0644'
                ).
                that_notifies('Exec[systemd-daemon-reload]')
            end

            is_expected.to contain_service('tmp.mount').
              with(
                'enable' => false,
                'ensure' => 'running'
              ).
              that_requires('Exec[systemd-daemon-reload]')
          else
            is_expected.not_to contain_file(filename)
            is_expected.not_to contain_service('tmp.mount')
          end
        }
      end

      context "on #{os} with enforce = #{enforce} and ensure = stopped" do
        let(:facts) { os_facts }
        let(:params) do
          {
            'enforce' => enforce,
            'size'    => 2,
            'enable'  => false,
            'ensure'  => 'stopped',
          }
        end

        it {
          is_expected.to compile

          if enforce
            is_expected.to contain_file('/etc/systemd/system/tmp.mount') unless os_facts[:os]['name'].casecmp('redhat').zero? && os_facts[:os]['release']['major'] > '7'

            is_expected.to contain_service('tmp.mount').
              with(
                'enable' => false,
                'ensure' => 'stopped'
              ).
              that_requires('Exec[systemd-daemon-reload]')
          else
            is_expected.not_to contain_service('tmp.mount')
          end
        }
      end
    end
  end
end
