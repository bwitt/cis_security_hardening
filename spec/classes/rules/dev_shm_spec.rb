# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::dev_shm' do
  on_supported_os.each do |os, _os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce} and an fstab entry for /dev/shm" do
        let(:facts) do
          {
            mountpoints: {
              '/dev/shm': {
                available: '1.85 GiB',
              },
            },
            cis_security_hardening: {
              fstab_mountpoints: {
                '/dev/shm': {
                  device: 'tmpfs',
                  fstype: 'tmpfs',
                  mountoptions: 'defaults',
                },
              },
            },
          }
        end
        let(:params) do
          {
            'enforce' => enforce,
            'size'    => 2,
          }
        end

        it {
          is_expected.to compile
          if enforce
            is_expected.to contain_cis_security_hardening__set_mount_options('/dev/shm-nodev').
              with('mountpoint' => '/dev/shm', 'mountoptions' => 'nodev')
            is_expected.to contain_cis_security_hardening__set_mount_options('/dev/shm-noexec').
              with('mountpoint' => '/dev/shm', 'mountoptions' => 'noexec')
            is_expected.to contain_cis_security_hardening__set_mount_options('/dev/shm-nosuid').
              with('mountpoint' => '/dev/shm', 'mountoptions' => 'nosuid')
            is_expected.to contain_cis_security_hardening__set_mount_options('/dev/shm-size').
              with('mountpoint' => '/dev/shm', 'mountoptions' => 'size=2G')
          else
            is_expected.not_to contain_cis_security_hardening__set_mount_options('/dev/shm-nodev')
            is_expected.not_to contain_cis_security_hardening__set_mount_options('/dev/shm-noexec')
            is_expected.not_to contain_cis_security_hardening__set_mount_options('/dev/shm-nosuid')
            is_expected.not_to contain_cis_security_hardening__set_mount_options('/dev/shm-size')
          end
        }
      end

      context "on #{os} with enforce = #{enforce} and no fstab entry for /dev/shm" do
        let(:facts) do
          {
            mountpoints: {
              '/dev/shm': {
                available: '1.85 GiB',
              },
            },
            cis_security_hardening: {
              fstab_mountpoints: {},
            },
          }
        end
        let(:params) do
          {
            'enforce' => enforce,
            'size'    => 2,
          }
        end

        it {
          is_expected.to compile
          is_expected.not_to contain_cis_security_hardening__set_mount_options('/dev/shm-nodev')
          is_expected.not_to contain_cis_security_hardening__set_mount_options('/dev/shm-noexec')
          is_expected.not_to contain_cis_security_hardening__set_mount_options('/dev/shm-nosuid')
          is_expected.not_to contain_cis_security_hardening__set_mount_options('/dev/shm-size')
        }
      end
    end
  end
end
