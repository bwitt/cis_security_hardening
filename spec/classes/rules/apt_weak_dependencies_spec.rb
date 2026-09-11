# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::apt_weak_dependencies' do
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
            is_expected.to contain_file('/etc/apt/apt.conf.d/60-no-weak-dependencies').
              with(
                'owner' => 'root',
                'group' => 'root',
                'mode'  => '0644'
              ).
              with_content(%r{^APT::Install-Recommends "0";$}).
              with_content(%r{^APT::Install-Suggests "0";$})
          else
            is_expected.not_to contain_file('/etc/apt/apt.conf.d/60-no-weak-dependencies')
          end
        }
      end
    end
  end
end
