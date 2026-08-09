# frozen_string_literal: true

require 'spec_helper_acceptance'

pp = <<-MANIFEST
  include cis_security_hardening
MANIFEST

describe 'cis_security_hardening class' do
  context 'with default parameters' do
    it 'works with no errors' do
      apply_manifest(pp, catch_failures: true)

      expect(file('/usr/share/cis_security_hardening')).to be_directory
      expect(file('/usr/share/cis_security_hardening/logs')).to be_directory
    end

    it 'is idempotent' do
      apply_manifest(pp, catch_changes: true)
    end

    # Only rules that are enforce: true in every data/cis params file
    describe 'sshd rules' do
      {
        'X11Forwarding' => 'no',
        'IgnoreRhosts' => 'yes',
        'HostbasedAuthentication' => 'no',
      }.each do |directive, value|
        it "sets #{directive} #{value}" do
          expect(shell("grep -E '^#{directive}\\s' /etc/ssh/sshd_config").stdout).to match(%r{^#{directive}\s+#{value}$})
        end
      end

      # log_level is Enum[INFO, VERBOSE], chosen per platform
      it 'sets LogLevel to an allowed value' do
        expect(shell("grep -E '^LogLevel\\s' /etc/ssh/sshd_config").stdout).to match(%r{^LogLevel\s+(INFO|VERBOSE)$})
      end

      it 'honours the acceptance override for PermitRootLogin' do
        expect(shell("grep -E '^PermitRootLogin\\s' /etc/ssh/sshd_config").stdout).to match(%r{^PermitRootLogin\s+yes$})
      end

      it 'leaves sshd able to accept new connections' do
        expect(shell('sshd -t; echo $?').stdout.strip).to eq('0')
      end
    end

    describe 'auditd rules' do
      it 'sets max_log_file in auditd.conf' do
        expect(shell('grep -E "^max_log_file\s*=" /etc/audit/auditd.conf').stdout).to match(%r{max_log_file\s*=\s*\d+})
      end
    end
  end
end
