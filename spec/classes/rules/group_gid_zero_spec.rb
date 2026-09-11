# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::group_gid_zero' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'cis_security_hardening' => {
              'accounts' => {
                'gid_zero_groups' => %w[roguegroup],
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
            is_expected.to contain_notify('group roguegroup has GID 0 but is not root').
              with(
                'loglevel' => 'warning'
              )
          else
            is_expected.not_to contain_notify('group roguegroup has GID 0 but is not root')
          end
        }
      end
    end

    context "on #{os} with enforce = true and no other groups with GID 0" do
      let(:facts) do
        os_facts.merge(
          'cis_security_hardening' => {
            'accounts' => {
              'gid_zero_groups' => [],
            },
          }
        )
      end
      let(:params) do
        {
          'enforce' => true,
        }
      end

      it {
        is_expected.to compile
        is_expected.not_to contain_notify('group roguegroup has GID 0 but is not root')
      }
    end
  end
end
