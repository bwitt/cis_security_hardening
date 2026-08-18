# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::root_umask' do
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
            is_expected.to contain_file('/root/.bash_profile').
              with(
                'ensure' => 'file',
                'owner'  => 'root',
                'group'  => 'root',
                'mode'   => '0644'
              )
            is_expected.to contain_file_line('root umask bash_profile').
              with(
                'path' => '/root/.bash_profile',
                'line' => 'umask 027'
              )
            is_expected.to contain_file_line('root umask bashrc').
              with(
                'path' => '/root/.bashrc',
                'line' => 'umask 027'
              )
          else
            is_expected.not_to contain_file('/root/.bash_profile')
            is_expected.not_to contain_file_line('root umask bash_profile')
            is_expected.not_to contain_file_line('root umask bashrc')
          end
        }
      end
    end

    context "on #{os} with a custom default_umask" do
      let(:facts) { os_facts }
      let(:params) do
        {
          'enforce'       => true,
          'default_umask' => '077',
        }
      end

      it {
        is_expected.to compile
        is_expected.to contain_file_line('root umask bash_profile').with('line' => 'umask 077')
        is_expected.to contain_file_line('root umask bashrc').with('line' => 'umask 077')
      }
    end
  end
end
