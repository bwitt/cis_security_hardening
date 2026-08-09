# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]
size_options = [0, 2]

create_changes = [
  'set 01/spec tmpfs',
  'set 01/file /dev/shm',
  'set 01/vfstype tmpfs',
  'set 01/opt defaults',
  'set 01/dump 0',
  'set 01/passno 0',
]

describe 'cis_security_hardening::rules::dev_shm' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      size_options.each do |size|
        context "on #{os} with enforce = #{enforce} and size = #{size}" do
          let(:params) do
            {
              'enforce' => enforce,
              'size'    => size,
            }
          end

          let(:facts) { os_facts }

          it {
            is_expected.to compile

            is_expected.not_to contain_file_line('add /dev/shm to fstab')

            if enforce
              is_expected.to contain_augeas('add /dev/shm to fstab').
                with(
                  'context' => '/files/etc/fstab',
                  'changes' => create_changes,
                  'onlyif'  => "match *[file = '/dev/shm'] size == 0"
                )

              if size > 0
                is_expected.to contain_cis_security_hardening__set_mount_options('/dev/shm-size').
                  with(
                    'mountpoint'   => '/dev/shm',
                    'mountoptions' => "size=#{size}G"
                  ).
                  that_requires('Augeas[add /dev/shm to fstab]')
              else
                is_expected.not_to contain_cis_security_hardening__set_mount_options('/dev/shm-size')
              end

              if os_facts.dig(:os, 'selinux', 'enabled')
                is_expected.to contain_cis_security_hardening__set_mount_options('/dev/shm-seclabel').
                  with(
                    'mountpoint'   => '/dev/shm',
                    'mountoptions' => 'seclabel'
                  ).
                  that_requires('Augeas[add /dev/shm to fstab]')
              else
                is_expected.not_to contain_cis_security_hardening__set_mount_options('/dev/shm-seclabel')
              end
            else
              is_expected.not_to contain_augeas('add /dev/shm to fstab')
              is_expected.not_to contain_cis_security_hardening__set_mount_options('/dev/shm-size')
              is_expected.not_to contain_cis_security_hardening__set_mount_options('/dev/shm-seclabel')
            end
          }
        end
      end
    end

    context "on #{os} with enforce = true alongside the option rules" do
      let(:pre_condition) do
        <<-EOF
          class { 'cis_security_hardening::rules::dev_shm_nodev':  enforce => true }
          class { 'cis_security_hardening::rules::dev_shm_nosuid': enforce => true }
          class { 'cis_security_hardening::rules::dev_shm_noexec': enforce => true }
        EOF
      end

      let(:params) do
        {
          'enforce' => true,
          'size'    => 0,
        }
      end

      let(:facts) do
        os_facts.merge(
          mountpoints: {
            '/dev/shm': {
              available: '1.85 GiB',
            },
          }
        )
      end

      it {
        is_expected.to compile

        %w[nodev nosuid noexec].each do |opt|
          is_expected.to contain_cis_security_hardening__set_mount_options("/dev/shm-#{opt}").
            with('mountpoint' => '/dev/shm', 'mountoptions' => opt)

          is_expected.to contain_augeas("/etc/fstab - work on /dev/shm with #{opt}").
            with(
              'changes' => [
                "ins opt after /files/etc/fstab/*[file = '/dev/shm']/opt[last()]",
                "set *[file = '/dev/shm']/opt[last()] #{opt}",
              ],
              'onlyif' => "match *[file = '/dev/shm']/opt[. = '#{opt}'] size == 0"
            ).
            that_requires('Augeas[add /dev/shm to fstab]')
        end
      }
    end
  end
end
