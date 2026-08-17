# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::passwd_last_change_date' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'cis_security_hardening' => {
              'local_users' => {
                'futureuser' => {
                  'account_expires_days' => 25,
                  'last_password_change_days' => -30,
                  'max_days_between_password_change' => 120,
                  'min_days_between_password_change' => 14,
                  'password_date_valid' => false,
                  'password_expires_days' => 82,
                  'password_inactive_days' => 35,
                  'warn_days_between_password_change' => 7,
                },
                'validuser' => {
                  'account_expires_days' => 25,
                  'last_password_change_days' => 8,
                  'max_days_between_password_change' => 120,
                  'min_days_between_password_change' => 14,
                  'password_date_valid' => true,
                  'password_expires_days' => 82,
                  'password_inactive_days' => 35,
                  'warn_days_between_password_change' => 7,
                },
                'neverchangeduser' => {
                  'account_expires_days' => 'never',
                  'last_password_change_days' => 'password must be changed',
                  'max_days_between_password_change' => 120,
                  'min_days_between_password_change' => 14,
                  'password_expires_days' => 'never',
                  'password_inactive_days' => 'never',
                  'warn_days_between_password_change' => 7,
                },
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
            is_expected.to contain_exec('reset last password change date to today for futureuser').
              with(
                'command' => 'chage -d $(date +%Y-%m-%d) futureuser',
                'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin']
              )
            is_expected.not_to contain_exec('reset last password change date to today for validuser')
            is_expected.not_to contain_exec('reset last password change date to today for neverchangeduser')
          else
            is_expected.not_to contain_exec('reset last password change date to today for futureuser')
          end
        }
      end
    end
  end
end
