# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::passwd_duplicate_uid' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'cis_security_hardening' => {
              'accounts' => {
                'duplicate_uids' => { '1000' => %w[userone usertwo] },
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
            is_expected.to contain_notify('duplicate UID 1000').
              with(
                'loglevel' => 'warning',
                'message'  => "CIS: UID '1000' is shared by multiple accounts (userone, usertwo)"
              )
          else
            is_expected.not_to contain_notify('duplicate UID 1000')
          end
        }
      end
    end
  end
end
