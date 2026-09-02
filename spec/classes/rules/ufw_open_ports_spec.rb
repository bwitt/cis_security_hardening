# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::ufw_open_ports' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
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
            'firewall_rules' => {
              'allow ssh' => {
                'queue' => 'in',
                'port' => '22',
                'proto' => 'tcp',
                'action' => 'allow',
                'from' => 'any',
                'to' => 'any',
              },
              'allow DNS inbound' => {
                'queue' => 'in',
                'port' => '53',
                'proto' => 'udp',
                'action' => 'allow',
                'from' => 'any',
                'to' => 'any',
              },
              'allow http outbound' => {
                'queue' => 'out',
                'to' => 'any',
                'port' => '80',
                'proto' => 'tcp',
                'action' => 'allow',
              },
              'allow ssh from cidr' => {
                'queue' => 'in',
                'port' => '22',
                'proto' => 'tcp',
                'action' => 'allow',
                'from' => '192.168.1.0/24',
                'to' => 'any',
              },
              'allow speedify data integer port' => {
                'queue' => 'in',
                'port' => 8443,
                'proto' => 'tcp',
                'action' => 'allow',
                'from' => 'any',
                'to' => 'any',
              },
              'allow speedify data range' => {
                'queue' => 'in',
                'port' => '37000:38000',
                'proto' => 'tcp',
                'action' => 'allow',
                'from' => 'any',
                'to' => 'any',
              },
            },
          }
        end

        it {
          is_expected.to compile

          if enforce
            is_expected.to contain_exec('allow ssh').
              with(
                'command' => 'ufw allow proto tcp from any to any port 22',
                'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
                'onlyif'  => 'test -z "$(ufw status verbose | grep -E -i \'^22/tcp.*ALLOW in\')"'
              )
            is_expected.to contain_exec('allow DNS inbound').
              with(
                'command' => 'ufw allow proto udp from any to any port 53',
                'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
                'onlyif'  => 'test -z "$(ufw status verbose | grep -E -i \'^53/udp.*ALLOW in\')"'
              )
            is_expected.to contain_exec('allow ssh from cidr').
              with(
                'command' => 'ufw allow proto tcp from 192.168.1.0/24 to any port 22',
                'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
                'onlyif'  => 'test -z "$(ufw status verbose | grep -E -i \'^22/tcp.*ALLOW in.*192.168.1.0/24\')"'
              )
            is_expected.to contain_exec('allow speedify data integer port').
              with(
                'command' => 'ufw allow proto tcp from any to any port 8443',
                'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
                'onlyif'  => 'test -z "$(ufw status verbose | grep -E -i \'^8443/tcp.*ALLOW in\')"'
              )
            is_expected.to contain_exec('allow speedify data range').
              with(
                'command' => 'ufw allow proto tcp from any to any port 37000:38000',
                'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
                'onlyif'  => 'test -z "$(ufw status verbose | grep -E -i \'^37000:38000/tcp.*ALLOW in\')"'
              )
          else
            is_expected.not_to contain_exec('allow ssh')
            is_expected.not_to contain_exec('allow DNS inbound')
          end
        }
      end
    end
  end
end
