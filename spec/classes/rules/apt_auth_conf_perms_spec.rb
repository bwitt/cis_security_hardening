# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::apt_auth_conf_perms' do
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

          ['/etc/apt/auth.conf.d'].each do |dir|
            if enforce
              is_expected.to contain_recursive_file_permissions(dir).
                with(
                  'dir_mode'  => '0755',
                  'file_mode' => '0640',
                  'owner'     => 'root',
                  'group'     => 'root'
                )
            else
              is_expected.not_to contain_recursive_file_permissions(dir)
            end
          end
        }
      end
    end
  end
end
