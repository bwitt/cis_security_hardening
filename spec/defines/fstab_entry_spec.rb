# frozen_string_literal: true

require 'spec_helper'

describe 'cis_security_hardening::fstab_entry' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }
      let(:title) { '/boot/efi' }

      context 'with options carrying a value' do
        let(:params) do
          {
            'mountpoint'   => '/boot/efi',
            'spec'         => 'UUID=BC04-FDA2',
            'fstype'       => 'vfat',
            'mountoptions' => ['umask=0077', 'fmask=0077', 'uid=0', 'gid=0'],
            'dump'         => 0,
            'passno'       => 1,
          }
        end

        it {
          is_expected.to compile
          is_expected.to contain_augeas('/etc/fstab - single entry for /boot/efi').
            with(
              'lens'    => 'Fstab.lns',
              'incl'    => '/etc/fstab',
              'context' => '/files/etc/fstab',
              'changes' => [
                "rm *[file = '/boot/efi']",
                'set 01/spec UUID=BC04-FDA2',
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
        }

        # An onlyif would let duplicates survive once one entry already matches,
        # which is the bug this define exists to fix
        it {
          is_expected.to contain_augeas('/etc/fstab - single entry for /boot/efi').without_onlyif
        }

        it 'removes existing entries before adding the canonical one' do
          changes = catalogue.resource('augeas', '/etc/fstab - single entry for /boot/efi')[:changes]
          expect(changes.first).to eq("rm *[file = '/boot/efi']")
          expect(changes.grep(%r{^rm }).size).to eq(1)
        end
      end

      context 'with valueless options and defaults' do
        let(:title) { '/mnt/data' }
        let(:params) do
          {
            'mountpoint'   => '/mnt/data',
            'spec'         => 'UUID=1c1cd60f-9c1e-4b5f-bd4b-6b2d2a2ee1b1',
            'fstype'       => 'ext4',
            'mountoptions' => %w[defaults nodev],
          }
        end

        it {
          is_expected.to compile
          is_expected.to contain_augeas('/etc/fstab - single entry for /mnt/data').
            with(
              'changes' => [
                "rm *[file = '/mnt/data']",
                'set 01/spec UUID=1c1cd60f-9c1e-4b5f-bd4b-6b2d2a2ee1b1',
                'set 01/file /mnt/data',
                'set 01/vfstype ext4',
                'set 01/opt[1] defaults',
                'set 01/opt[2] nodev',
                'set 01/dump 0',
                'set 01/passno 0',
              ]
            )
        }
      end

      context 'with an option value containing an equals sign' do
        let(:title) { '/dev/shm' }
        let(:params) do
          {
            'mountpoint'   => '/dev/shm',
            'spec'         => 'tmpfs',
            'fstype'       => 'tmpfs',
            'mountoptions' => ['sec=krb5:krb5i'],
          }
        end

        it {
          is_expected.to compile
          is_expected.to contain_augeas('/etc/fstab - single entry for /dev/shm').
            with_changes(
              [
                "rm *[file = '/dev/shm']",
                'set 01/spec tmpfs',
                'set 01/file /dev/shm',
                'set 01/vfstype tmpfs',
                'set 01/opt[1] sec',
                'set 01/opt[1]/value krb5:krb5i',
                'set 01/dump 0',
                'set 01/passno 0',
              ]
            )
        }
      end

      context 'with a non default target' do
        let(:params) do
          {
            'mountpoint' => '/boot/efi',
            'spec'       => 'UUID=BC04-FDA2',
            'fstype'     => 'vfat',
            'target'     => '/tmp/fstab-fixture',
          }
        end

        it {
          is_expected.to compile
          is_expected.to contain_augeas('/tmp/fstab-fixture - single entry for /boot/efi').
            with(
              'lens'    => 'Fstab.lns',
              'incl'    => '/tmp/fstab-fixture',
              'context' => '/files/tmp/fstab-fixture'
            )
        }
      end

      context 'with a spec containing whitespace' do
        let(:params) do
          {
            'mountpoint' => '/boot/efi',
            'spec'       => 'UUID=BC04-FDA2 /boot/efi vfat',
            'fstype'     => 'vfat',
          }
        end

        it { is_expected.to compile.and_raise_error(%r{parameter 'spec'}) }
      end
    end
  end
end
