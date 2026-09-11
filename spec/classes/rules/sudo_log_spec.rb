# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]
log_methods = %w[logfile syslog]

describe 'cis_security_hardening::rules::sudo_log' do
  let(:pre_condition) do
    <<-EOF
    exec { 'reload-rsyslog':
      command     => 'pkill -HUP rsyslog',
      path        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      refreshonly => true,
    }
    EOF
  end

  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      log_methods.each do |log_method|
        context "on #{os} with enforce = #{enforce} and log_method = #{log_method}" do
          let(:facts) { os_facts }
          let(:params) do
            {
              'enforce' => enforce,
              'log_method' => log_method,
            }
          end

          it {
            is_expected.to compile

            if enforce && log_method == 'logfile'
              is_expected.to contain_file_line('sudo logfile').
                with(
                  'path'               => '/etc/sudoers',
                  'match'              => 'Defaults.*logfile\s*=',
                  'append_on_no_match' => true,
                  'line'               => "Defaults\tlogfile=\"/var/log/sudo.log\"",
                  'after'              => '# Defaults specification'
                )
              is_expected.not_to contain_file('/etc/rsyslog.d/30-sudo.conf')
            elsif enforce && log_method == 'syslog'
              # sudo-rs silently ignores "Defaults logfile=", so it must not be used
              is_expected.not_to contain_file_line('sudo logfile')
              is_expected.to contain_file('/etc/rsyslog.d/30-sudo.conf').
                with(
                  'owner'   => 'root',
                  'group'   => 'root',
                  'mode'    => '0640',
                  'content' => "# CIS 5.2.3 - durable sudo event capture\nauthpriv.*\t\t\t\t/var/log/sudo.log\n"
                )
              is_expected.to contain_file('/var/log/sudo.log').
                with(
                  'owner' => 'root',
                  'group' => 'adm',
                  'mode'  => '0640'
                )
            else
              is_expected.not_to contain_file_line('sudo logfile')
              is_expected.not_to contain_file('/etc/rsyslog.d/30-sudo.conf')
            end
          }
        end
      end
    end
  end
end
