# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::group_duplicate_groupname' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'cis_security_hardening' => {
              'accounts' => {
                'duplicate_groupnames' => %w[dupgroup],
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
            is_expected.to contain_notify('duplicate group name dupgroup').
              with('loglevel' => 'warning')
          else
            is_expected.not_to contain_notify('duplicate group name dupgroup')
          end
        }
      end
    end
  end
end
