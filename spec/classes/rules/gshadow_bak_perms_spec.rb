# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::gshadow_bak_perms' do
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
            if os_facts[:os]['name'].casecmp('debian').zero?
              is_expected.to contain_file('/etc/gshadow-').
                with(
                  'ensure' => 'file',
                  'owner'  => 'root',
                  'group'  => 'root',
                  'mode'   => '0640'
                )
            else
              is_expected.to contain_file('/etc/gshadow-').
                with(
                  'ensure' => 'file',
                  'owner'  => 'root',
                  'group'  => 'root',
                  'mode'   => '0000'
                )
            end
          else
            is_expected.not_to contain_file('/etc/gshadow-')
          end
        }
      end
    end

    context "on #{os} with mode and group overridden" do
      let(:facts) { os_facts }
      let(:params) do
        {
          'enforce' => true,
          'mode'    => '0640',
          'group'   => 'shadow',
        }
      end

      it {
        is_expected.to compile
        is_expected.to contain_file('/etc/gshadow-').
          with(
            'ensure' => 'file',
            'owner'  => 'root',
            'group'  => 'shadow',
            'mode'   => '0640'
          )
      }
    end
  end
end
