# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]
policies = %w[deny reject]

describe 'cis_security_hardening::rules::ufw_default_deny' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      policies.each do |policy|
        context "on #{os} with enforce = #{enforce} and policy = #{policy}" do
          let(:facts) do
            os_facts.merge(
              cis_security_hardening: {
                services_enabled: {
                  srv_ufw: 'disabled',
                },
                ufw: {
                  loopback_status: false,
                },
              }
            )
          end
          let(:params) do
            {
              'enforce' => enforce,
              'default_incoming' => policy,
              'default_outgoing' => policy,
              'default_routed' => policy,
            }
          end

          it {
            is_expected.to compile

            if enforce
              is_expected.to contain_exec("default incoming policy #{policy}").
                with(
                  'command' => "ufw default #{policy} incoming",
                  'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
                  'unless'  => "ufw status verbose | grep '#{policy} (incoming)'"
                )

              is_expected.to contain_exec("default outgoing policy #{policy}").
                with(
                  'command' => "ufw default #{policy} outgoing",
                  'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
                  'unless'  => "ufw status verbose | grep '#{policy} (outgoing)'"
                )

              is_expected.to contain_exec("default routed policy #{policy}").
                with(
                  'command' => "ufw default #{policy} routed",
                  'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
                  'unless'  => "ufw status verbose | grep -e '#{policy} (routed)' -e 'disabled (routed)'"
                )
            else
              is_expected.not_to contain_exec("default incoming policy #{policy}")
              is_expected.not_to contain_exec("default outgoing policy #{policy}")
              is_expected.not_to contain_exec("default routed policy #{policy}")
            end
          }
        end
      end

      context "on #{os} with enforce = #{enforce} and an unsupported policy" do
        let(:facts) { os_facts }
        let(:params) do
          {
            'enforce' => enforce,
            'default_incoming' => 'drop',
          }
        end

        it { is_expected.to compile.and_raise_error(%r{default_incoming}) }
      end
    end
  end
end
