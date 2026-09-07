# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::iptables_deny_policy' do
  let(:pre_condition) do
    <<-EOF
    exec { 'save iptables rules':
      command    => 'service iptables save',
      path       => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      unless     => 'test -z "$(grep -e AlmaLinux -e Rocky /etc/redhat-release 2>/dev/null)"',
      refreshonly => true,
    }

    firewall { '010 open ssh port inbound':
      chain => 'INPUT',
      proto => 'tcp',
      dport => 22,
      jump  => 'ACCEPT',
    }
    EOF
  end

  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) { os_facts }
        let(:params) do
          {
            'enforce' => enforce,
            'input_policy' => 'drop',
            'output_policy' => 'drop',
            'forward_policy' => 'drop',
          }
        end

        it {
          is_expected.to compile

          if enforce
            is_expected.to contain_firewallchain('OUTPUT:filter:IPv4').
              with(
                'ensure' => 'present',
                'policy' => 'drop'
              )

            is_expected.to contain_firewallchain('FORWARD:filter:IPv4').
              with(
                'ensure' => 'present',
                'policy' => 'drop'
              )

            is_expected.to contain_firewallchain('INPUT:filter:IPv4').
              with(
                'ensure' => 'present',
                'policy' => 'drop'
              )

            is_expected.to contain_firewall('010 open ssh port inbound').
              that_comes_before('Firewallchain[INPUT:filter:IPv4]')
          else
            is_expected.not_to contain_firewallchain('OUTPUT:filter:IPv4')
            is_expected.not_to contain_firewallchain('FORWARD:filter:IPv4')
            is_expected.not_to contain_firewallchain('INPUT:filter:IPv4')
          end
        }
      end
    end
  end
end
