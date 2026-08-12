# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]
enforce_for_root_options = [true, false]

describe 'cis_security_hardening::rules::pam_old_passwords' do
  let(:pre_condition) do
    <<-EOF
    exec { 'authselect-apply-changes':
      command     => '/bin/true',
      path        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      refreshonly => true,
    }
    EOF
  end

  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      enforce_for_root_options.each do |enforce_for_root|
        context "on #{os} with enforce = #{enforce} and enforce_for_root = #{enforce_for_root}" do
          let(:facts) do
            os_facts.merge(
              'cis_security_hardening' => {
                'authselect' => {
                  'profile' => 'minimal',
                },
              }
            )
          end
          let(:params) do
            {
              'enforce'          => enforce,
              'oldpasswords'     => 5,
              'enforce_for_root' => enforce_for_root,
            }
          end

          it {
            is_expected.to compile

            if enforce
              if os_facts[:os]['family'].casecmp('redhat').zero?
                if os_facts[:os]['release']['major'] > '7'
                  is_expected.to contain_exec('update authselect config for old passwords')
                else
                  is_expected.to contain_pam('pam-system-auth-pwhistory').with(
                    'ensure'    => 'present',
                    'service'   => 'system-auth',
                    'type'      => 'password',
                    'control'   => 'required',
                    'module'    => 'pam_pwhistory.so',
                    'arguments' => ['remember=5', 'use_auth_ok']
                  )
                  is_expected.to contain_pam('pam-password-auth-pwhistory').with(
                    'ensure'    => 'present',
                    'service'   => 'password-auth',
                    'type'      => 'password',
                    'control'   => 'required',
                    'module'    => 'pam_pwhistory.so',
                    'arguments' => ['remember=5', 'use_auth_ok']
                  )
                end
              elsif os_facts[:os]['family'].casecmp('debian').zero? || os_facts[:os]['family'].casecmp('suse').zero?
                if (os_facts[:os]['name'].casecmp('debian').zero? && os_facts[:os]['release']['major'].to_i > 10) ||
                   (os_facts[:os]['name'].casecmp('ubuntu').zero? && os_facts[:os]['release']['major'].to_i >= 22)
                  expected_arguments = if enforce_for_root
                                         ['use_authtok', 'enforce_for_root', 'remember=5']
                                       else
                                         ['use_authtok', 'remember=5']
                                       end
                  is_expected.to contain_pam('pam-common-password-requisite-pwhistory').with(
                    'ensure'    => 'present',
                    'service'   => 'common-password',
                    'type'      => 'password',
                    'control'   => 'required',
                    'module'    => 'pam_pwhistory.so',
                    'position'  => 'before *[type="password" and module="pam_unix.so"]',
                    'arguments' => expected_arguments
                  )
                elsif os_facts[:os]['name'].casecmp('ubuntu').zero? && os_facts[:os]['release']['major'].to_i >= 20
                  is_expected.to contain_pam('ubuntu-remember-old-pw').with(
                    'ensure'           => 'present',
                    'service'          => 'common-password',
                    'type'             => 'password',
                    'control'          => '[success=1 default=ignore]',
                    'control_is_param' => true,
                    'module'           => 'pam_unix.so',
                    'arguments'        => ['obscure', 'use_authtok', 'try_first_pass', 'yescrypt', 'remember=5'],
                    'position'         => 'before *[type="password" and module="pam_deny.so"]'
                  )
                else
                  is_expected.to contain_pam('pam-common-password-requisite-pwhistory').with(
                    'ensure'    => 'present',
                    'service'   => 'common-password',
                    'type'      => 'password',
                    'control'   => 'required',
                    'module'    => 'pam_pwhistory.so',
                    'arguments' => ['remember=5']
                  )
                end
              end
            else
              is_expected.not_to contain_pam('pam-system-auth-sufficient')
              is_expected.not_to contain_pam('pam-password-auth-sufficient')
              is_expected.not_to contain_exec('update authselect config for old passwords')
              is_expected.not_to contain_file('/etc/security/pwhistory.conf')
              is_expected.not_to contain_file_line('pwhistory remember')
            end
          }
        end
      end
    end
  end
end
