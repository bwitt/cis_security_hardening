# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::group_duplicate_gid' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'cis_security_hardening' => {
              'accounts' => {
                'duplicate_gids' => { '2000' => %w[groupone grouptwo] },
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
            is_expected.to contain_notify('duplicate GID 2000').
              with(
                'loglevel' => 'warning',
                'message'  => "CIS: GID '2000' is shared by multiple groups (groupone, grouptwo)"
              )
          else
            is_expected.not_to contain_notify('duplicate GID 2000')
          end
        }
      end
    end
  end
end
