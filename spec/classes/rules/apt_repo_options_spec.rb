# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::apt_repo_options' do
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
            is_expected.to contain_file('/etc/apt/apt.conf.d/99-no-insecure-repositories').
              with(
                'owner' => 'root',
                'group' => 'root',
                'mode'  => '0644'
              ).
              with_content(%r{^Acquire::AllowInsecureRepositories "0";$}).
              with_content(%r{^Acquire::AllowWeakRepositories "0";$}).
              with_content(%r{^Acquire::AllowDowngradeToInsecureRepositories "0";$}).
              with_content(%r{^Acquire::Check-Date "true";$})
          else
            is_expected.not_to contain_file('/etc/apt/apt.conf.d/99-no-insecure-repositories')
          end
        }
      end
    end
  end
end
