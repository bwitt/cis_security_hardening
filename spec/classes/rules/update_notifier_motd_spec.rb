# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::update_notifier_motd' do
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
          }
        end

        it {
          is_expected.to compile

          ['update-notifier-motd.service', 'update-notifier-motd.timer'].each do |unit|
            if enforce
              is_expected.to contain_exec("mask #{unit}").
                with(
                  'command' => "systemctl stop #{unit} ; systemctl mask #{unit}"
                ).
                that_notifies('Exec[systemd-daemon-reload]')
            else
              is_expected.not_to contain_exec("mask #{unit}")
            end
          end
        }
      end
    end
  end
end
