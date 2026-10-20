# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::grub_bootloader_config' do
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

          if enforce

            if os_facts[:os]['family'].casecmp('redhat').zero?
              is_expected.to contain_file('/boot/grub2/grub.cfg').
                with(
                  'ensure' => 'file',
                  'owner' => 'root',
                  'group' => 'root',
                  'mode' => '0400'
                )

              if os_facts[:os]['release']['major'] >= '9'
                is_expected.to contain_file('/boot/grub2/grubenv').
                  with(
                    'ensure' => 'file',
                    'owner' => 'root',
                    'group' => 'root',
                    'mode' => '0600'
                  )
                is_expected.to contain_file('/boot/grub2/user.cfg').
                  with(
                    'ensure' => 'file',
                    'owner' => 'root',
                    'group' => 'root',
                    'mode' => '0600'
                  )
              else
                is_expected.not_to contain_file('/boot/grub2/grubenv')
                is_expected.not_to contain_file('/boot/grub2/user.cfg')
              end

            elsif os_facts[:os]['family'].casecmp('debian').zero?
              is_expected.to contain_file('/boot/grub/grub.cfg').
                with(
                  'ensure' => 'file',
                  'owner' => 'root',
                  'group' => 'root',
                  'mode' => '0400'
                )
              is_expected.to contain_file_line('correct grub.cfg permissions').
                with(
                  'path'               => '/usr/sbin/grub-mkconfig',
                  'line'               => '  chmod 400 ${grub_cfg}.new || true',
                  'match'              => '\s+chmod.*444',
                  'multiple'           => true,
                  'append_on_no_match' => false
                )
            elsif os_facts[:os]['family'].casecmp('suse').zero?
              is_expected.to contain_file('/boot/grub2/grub.cfg').
                with(
                  'ensure' => 'file',
                  'owner' => 'root',
                  'group' => 'root',
                  'mode' => '0400'
                )
            else
              is_expected.not_to contain_file('/boot/grub2/grub.cfg')
              is_expected.not_to contain_file('/boot/grub/grub.cfg')
              is_expected.not_to contain_file('/boot/grub2/grubenv')
              is_expected.not_to contain_file('/boot/grub2/user.cfg')
            end

          else
            is_expected.not_to contain_file('/boot/grub2/grub.cfg')
            is_expected.not_to contain_file('/boot/grub/grub.cfg')
            is_expected.not_to contain_file('/boot/grub2/grubenv')
            is_expected.not_to contain_file('/boot/grub2/user.cfg')
          end
        }
      end

      context "on #{os} with enforce = #{enforce} and efi boot" do
        let(:facts) do
          os_facts.merge(
            'cis_security_hardening' => {
              'efi' => true,
            },
            'mountpoints' => {
              '/boot/efi' => {
                'available' => '732.21 MiB',
                'available_bytes' => 767_782_912,
                'capacity' => '20.71%',
                'device' => '/dev/sda1',
                'filesystem' => 'ext3',
                'options' => %w[rw relatime],
                'size' => '974.67 MiB',
                'size_bytes' => 1_022_013_440,
                'used' => '191.25 MiB',
                'used_bytes' => 200_544_256
              },
            },
            'partitions' => {
              '/dev/sda1' => {
                'filesystem' => 'ext3',
                'mount' => '/boot/efi',
                'partuuid' => '931e1103-01',
                'size' => '1.00 GiB',
                'size_bytes' => 1_073_741_824,
                'uuid' => '583bc67c-8dfa-42f2-9022-6d3161d34521'
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
            is_expected.to contain_cis_security_hardening__fstab_entry('/boot/efi').
              with(
                'mountpoint'   => '/boot/efi',
                'spec'         => 'UUID=583bc67c-8dfa-42f2-9022-6d3161d34521',
                'fstype'       => 'vfat',
                'mountoptions' => ['umask=0077', 'fmask=0077', 'uid=0', 'gid=0'],
                'dump'         => 0,
                'passno'       => 1
              )
            is_expected.not_to contain_file_line('fix /boot/efi')

            # The entry has to be addressed by mountpoint, that is what removes duplicates
            is_expected.to contain_augeas('/etc/fstab - single entry for /boot/efi').
              with_changes(
                [
                  "rm *[file = '/boot/efi']",
                  'set 01/spec UUID=583bc67c-8dfa-42f2-9022-6d3161d34521',
                  'set 01/file /boot/efi',
                  'set 01/vfstype vfat',
                  'set 01/opt[1] umask',
                  'set 01/opt[1]/value 0077',
                  'set 01/opt[2] fmask',
                  'set 01/opt[2]/value 0077',
                  'set 01/opt[3] uid',
                  'set 01/opt[3]/value 0',
                  'set 01/opt[4] gid',
                  'set 01/opt[4]/value 0',
                  'set 01/dump 0',
                  'set 01/passno 1',
                ]
              )

            if os_facts[:os]['family'].casecmp('redhat').zero?
              is_expected.to contain_file('/boot/grub2/grub.cfg').
                with(
                  'ensure' => 'file',
                  'owner' => 'root',
                  'group' => 'root',
                  'mode' => '0400'
                )

              if os_facts[:os]['release']['major'] >= '9'
                is_expected.to contain_file('/boot/grub2/grubenv').
                  with(
                    'ensure' => 'file',
                    'owner' => 'root',
                    'group' => 'root',
                    'mode' => '0600'
                  )
                is_expected.to contain_file('/boot/grub2/user.cfg').
                  with(
                    'ensure' => 'file',
                    'owner' => 'root',
                    'group' => 'root',
                    'mode' => '0600'
                  )
              else
                is_expected.not_to contain_file('/boot/grub2/grubenv')
                is_expected.not_to contain_file('/boot/grub2/user.cfg')
              end

            elsif os_facts[:os]['family'].casecmp('debian').zero?
              is_expected.to contain_file('/boot/grub/grub.cfg').
                with(
                  'ensure' => 'file',
                  'owner' => 'root',
                  'group' => 'root',
                  'mode' => '0400'
                )
              is_expected.to contain_file_line('correct grub.cfg permissions').
                with(
                  'path'               => '/usr/sbin/grub-mkconfig',
                  'line'               => '  chmod 400 ${grub_cfg}.new || true',
                  'match'              => '\s+chmod.*444',
                  'multiple'           => true,
                  'append_on_no_match' => false
                )
            elsif os_facts[:os]['family'].casecmp('suse').zero?
              is_expected.to contain_file('/boot/grub2/grub.cfg').
                with(
                  'ensure' => 'file',
                  'owner' => 'root',
                  'group' => 'root',
                  'mode' => '0400'
                )
            else
              is_expected.not_to contain_file('/boot/grub2/grub.cfg')
              is_expected.not_to contain_file('/boot/grub/grub.cfg')
              is_expected.not_to contain_file('/boot/grub2/grubenv')
              is_expected.not_to contain_file('/boot/grub2/user.cfg')
            end

          else
            is_expected.not_to contain_class('cis_security_hardening::grub_package')
            is_expected.not_to contain_file('/boot/grub2/grub.cfg')
            is_expected.not_to contain_file('/boot/grub/grub.cfg')
            is_expected.not_to contain_file('/boot/grub2/grubenv')
            is_expected.not_to contain_file('/boot/grub2/user.cfg')
            is_expected.not_to contain_file_line('fix /boot/efi')
            is_expected.not_to contain_cis_security_hardening__fstab_entry('/boot/efi')
          end
        }
      end

      context "on #{os} with enforce = #{enforce}, efi boot and no partition uuid" do
        let(:facts) do
          os_facts.merge(
            'cis_security_hardening' => {
              'efi' => true,
            },
            'mountpoints' => {
              '/boot/efi' => {
                'device' => '/dev/sda1',
                'filesystem' => 'vfat',
                'options' => %w[rw relatime],
              },
            },
            'partitions' => {}
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
          }
        end

        # A missing uuid would produce "UUID=" as the device, fstab must be left alone
        it {
          is_expected.to compile
          is_expected.not_to contain_cis_security_hardening__fstab_entry('/boot/efi')
          is_expected.not_to contain_augeas('/etc/fstab - single entry for /boot/efi')
        }
      end
    end
  end
end
