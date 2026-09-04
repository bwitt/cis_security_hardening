# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]
mask_options = [true, false]

describe 'cis_security_hardening::rules::systemd_journal_remote_receive' do
  let(:pre_condition) do
    <<-EOF
    exec { 'systemd-daemon-reload':
      command     => 'systemctl daemon-reload',
      path        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      refreshonly => true,
    }
    EOF
  end

  enforce_options.each do |enforce|
    mask_options.each do |mask|
      context "on Ubuntu with enforce #{enforce} and mask #{mask}" do
        let(:facts) do
          {
            'os' => {
              'architecture' => 'x86_64',
              'family' => 'Debian',
              'name' => 'Ubuntu',
              'release' => {
                'major' => '26.04',
              }
            }
          }
        end
        let(:params) do
          {
            'enforce' => enforce,
            'mask' => mask,
            'units' => ['systemd-journal-remote.socket', 'systemd-journal-remote.service'],
          }
        end

        it {
          is_expected.to compile.with_all_deps

          ['systemd-journal-remote.socket', 'systemd-journal-remote.service'].each do |unit|
            if enforce
              is_expected.to contain_service(unit).
                with(
                  'ensure' => 'stopped',
                  'enable' => false
                )
              if mask
                is_expected.to contain_exec("mask #{unit}").
                  with('command' => "systemctl mask #{unit}").
                  that_requires("Service[#{unit}]").
                  that_notifies('Exec[systemd-daemon-reload]')
              else
                is_expected.not_to contain_exec("mask #{unit}")
              end
            else
              is_expected.not_to contain_service(unit)
              is_expected.not_to contain_exec("mask #{unit}")
            end
          end
        }
      end
    end
  end

  context 'defaults keep the previous behaviour' do
    let(:facts) do
      {
        'os' => {
          'architecture' => 'x86_64',
          'family' => 'Debian',
          'name' => 'Ubuntu',
          'release' => { 'major' => '24.04' }
        }
      }
    end
    let(:params) { { 'enforce' => true } }

    it {
      is_expected.to compile.with_all_deps
      is_expected.to contain_service('systemd-journal-remote.socket').with('ensure' => 'stopped')
      is_expected.not_to contain_service('systemd-journal-remote.service')
      is_expected.not_to contain_exec('mask systemd-journal-remote.socket')
    }
  end
end
