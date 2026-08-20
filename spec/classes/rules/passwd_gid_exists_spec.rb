# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::passwd_gid_exists' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'cis_security_hardening' => {
              'accounts' => {
                'orphan_gid_users' => %w[orphaneduser],
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
            is_expected.to contain_notify('user orphaneduser has a GID that does not exist in /etc/group').
              with('loglevel' => 'warning')
          else
            is_expected.not_to contain_notify('user orphaneduser has a GID that does not exist in /etc/group')
          end
        }
      end
    end
  end
end
