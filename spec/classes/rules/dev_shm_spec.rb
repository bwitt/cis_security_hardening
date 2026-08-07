# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::dev_shm' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:params) do
          {
            'enforce' => enforce,
            'size'    => 2,
          }
        end

        let(:facts) { os_facts }

        it {
          is_expected.to compile
          if enforce
            is_expected.to contain_file_line('add /dev/shm to fstab').
              with(
                'ensure'             => 'present',
                'path'               => '/etc/fstab',
                'match'              => '^tmpfs\\s* /dev/shm',
                'line'               => 'tmpfs   /dev/shm        tmpfs   defaults,size=2G,nodev,nosuid,noexec,seclabel   0 0',
                'append_on_no_match' => true
              ).
              that_notifies('Exec[remount /dev/shm]')

            is_expected.to contain_exec('remount /dev/shm').
              with(
                'command'     => 'mount -o remount /dev/shm',
                'refreshonly' => true
              )
          else
            is_expected.not_to contain_file_line('add /dev/shm to fstab')
            is_expected.not_to contain_exec('remount /dev/shm')
          end
        }
      end
    end
  end

  os, os_facts = on_supported_os.first

  context "on #{os} with individual options toggled off" do
    let(:facts) { os_facts }

    context 'enforce_noexec => false' do
      let(:params) do
        {
          'enforce'        => true,
          'size'           => 0,
          'enforce_noexec' => false,
        }
      end

      it {
        is_expected.to contain_file_line('add /dev/shm to fstab').
          with('line' => 'tmpfs   /dev/shm        tmpfs   defaults,nodev,nosuid,seclabel   0 0')
      }
    end

    context 'enforce_nodev => false and enforce_nosuid => false' do
      let(:params) do
        {
          'enforce'        => true,
          'size'           => 0,
          'enforce_nodev'  => false,
          'enforce_nosuid' => false,
        }
      end

      it {
        is_expected.to contain_file_line('add /dev/shm to fstab').
          with('line' => 'tmpfs   /dev/shm        tmpfs   defaults,noexec,seclabel   0 0')
      }
    end

    context 'all three options disabled' do
      let(:params) do
        {
          'enforce'        => true,
          'size'           => 0,
          'enforce_nodev'  => false,
          'enforce_noexec' => false,
          'enforce_nosuid' => false,
        }
      end

      it {
        is_expected.to contain_file_line('add /dev/shm to fstab').
          with('line' => 'tmpfs   /dev/shm        tmpfs   defaults,seclabel   0 0')
      }
    end
  end
end
