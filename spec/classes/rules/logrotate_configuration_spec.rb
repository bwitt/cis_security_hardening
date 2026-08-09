# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::logrotate_configuration' do
  enforce_options.each do |enforce|
    on_supported_os.each do |os, os_facts|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            cis_security_hardening: {
              logrotate_conf: {
                '/etc/logrotate.d/alternatives' => [
                  {
                    'action' => 'create',
                    'group' => 'root',
                    'mode' => '644',
                    'user' => 'root'
                  },
                ],
              },
            }
          )
        end
        let(:params) do
          {
            'enforce'    => enforce,
            'permission' => '640'
          }
        end

        it {
          is_expected.to compile

          if enforce
            is_expected.to contain_file_line('change /etc/logrotate.d/alternatives 0').
              with(
                'ensure' => 'present',
                'path'   => '/etc/logrotate.d/alternatives',
                'line'   => 'create 640 root root',
                'match'  => 'create 644 root root'
              )
          else
            is_expected.not_to contain_file_line('change /etc/logrotate.d/alternatives 0')
          end
        }
      end

      context "on #{os} with enforce = #{enforce} and two entries in one file" do
        let(:facts) do
          os_facts.merge(
            cis_security_hardening: {
              logrotate_conf: {
                '/etc/logrotate.conf' => [
                  {
                    'action' => 'create',
                    'group' => 'utmp',
                    'mode' => '0664',
                    'user' => 'root'
                  },
                  {
                    'action' => 'create',
                    'group' => 'utmp',
                    'mode' => '0660',
                    'user' => 'root'
                  },
                ],
              },
            }
          )
        end
        let(:params) do
          {
            'enforce'    => enforce,
            'permission' => '0640'
          }
        end

        it {
          is_expected.to compile

          if enforce
            # both non-compliant lines must be fixed, not just the last one
            is_expected.to contain_file_line('change /etc/logrotate.conf 0').
              with(
                'line'  => 'create 0640 root utmp',
                'match' => 'create 0664 root utmp'
              )
            is_expected.to contain_file_line('change /etc/logrotate.conf 1').
              with(
                'line'  => 'create 0640 root utmp',
                'match' => 'create 0660 root utmp'
              )
          else
            is_expected.not_to contain_file_line('change /etc/logrotate.conf 0')
          end
        }
      end
    end
  end
end
