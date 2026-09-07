# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::ip6tables_deny_policy' do
  let(:pre_condition) do
    <<-EOF
    firewall { '010-6 open ssh port inbound':
      chain    => 'INPUT',
      proto    => 'tcp',
      dport    => 22,
      jump     => 'ACCEPT',
      protocol => 'ip6tables',
    }
    EOF
  end

  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce} with ipv6" do
        let(:facts) do
          os_facts.merge(
            {
              'network6' => 'fe81::',
              'netmask6' => 'ffff:ffff:ffff:ffff::',
            }
          )
        end
        let(:params) do
          {
            'enforce'        => enforce,
            'input_policy'   => 'drop',
            'output_policy'  => 'drop',
            'forward_policy' => 'drop',
          }
        end

        it {
          is_expected.to compile

          if enforce
            is_expected.to contain_firewallchain('OUTPUT:filter:IPv6').
              with(
                'ensure' => 'present',
                'policy' => 'drop'
              )

            is_expected.to contain_firewallchain('FORWARD:filter:IPv6').
              with(
                'ensure' => 'present',
                'policy' => 'drop'
              )

            is_expected.to contain_firewallchain('INPUT:filter:IPv6').
              with(
                'ensure' => 'present',
                'policy' => 'drop'
              )

            is_expected.to contain_firewall('010-6 open ssh port inbound').
              that_comes_before('Firewallchain[INPUT:filter:IPv6]')
          else
            is_expected.not_to contain_firewallchain('OUTPUT:filter:IPv6')
            is_expected.not_to contain_firewallchain('FORWARD:filter:IPv6')
            is_expected.not_to contain_firewallchain('INPUT:filter:IPv6')
          end
        }
      end
    end
  end
end
