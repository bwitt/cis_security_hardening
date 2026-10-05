# frozen_string_literal: true

require 'spec_helper'
require 'facter/cis_security_hardening/common_facts'

describe 'common_facts' do
  # The exec commands common_facts issues, keyed for readability.
  let(:commands) do
    {
      pass_max_days: "grep ^PASS_MAX_DAYS /etc/login.defs | awk '{print $2;}'",
      pass_min_days: "grep ^PASS_MIN_DAYS /etc/login.defs | awk '{print $2;}'",
      pass_warn_age: "grep ^PASS_WARN_AGE /etc/login.defs | awk '{print $2;}'",
      inactive: 'useradd -D | grep INACTIVE | cut -f 2 -d =',
      postfix_rpm: 'rpm -q postfix 2>/dev/null',
      postfix_dpkg: "dpkg -l | grep postfix | awk '{print $2;}'",
      logrotate: 'grep -Es "^\s*create\s+\S+" /etc/logrotate.conf /etc/logrotate.d/* | grep -E -v "\s(0)?[0-6][04]0\s"',
    }
  end

  let(:login_defs) { { pass_max_days: '90', pass_min_days: '7', pass_warn_age: '7', inactive: '30' } }
  let(:local_users) { {} }

  before do
    # Collaborators are covered by their own specs; stub them out so this spec
    # only exercises what common_facts itself does.
    allow(self).to receive_messages(
      check_puppet_postrun_command: true,
      read_auditd_data: {},
      read_wlan_data: { 'wlan' => [] },
      read_local_users: local_users,
      read_sshd_config: {},
      read_open_ports: [],
      read_nfs_filesystems: {}
    )

    allow(File).to receive(:exist?).and_call_original
    allow(File).to receive(:exist?).with('/usr/share/cis_security_hardening/data/world-writable-files.txt').and_return(false)
    allow(File).to receive(:directory?).with('/sys/firmware/efi').and_return(false)

    allow(Facter::Core::Execution).to receive(:exec).and_return('')
    allow(Facter::Core::Execution).to receive(:exec).with(commands[:pass_max_days]).and_return(login_defs[:pass_max_days])
    allow(Facter::Core::Execution).to receive(:exec).with(commands[:pass_min_days]).and_return(login_defs[:pass_min_days])
    allow(Facter::Core::Execution).to receive(:exec).with(commands[:pass_warn_age]).and_return(login_defs[:pass_warn_age])
    allow(Facter::Core::Execution).to receive(:exec).with(commands[:inactive]).and_return(login_defs[:inactive])
  end

  describe 'pass_min_days_status' do
    # These were compared as Strings, so '10' < '7' was true and any compliant
    # two digit value was reported as non-compliant.
    {
      '0' => true, '5' => true, '6' => true,
      '7' => false, '10' => false, '14' => false, '30' => false
    }.each do |value, expected|
      context "with PASS_MIN_DAYS #{value}" do
        let(:login_defs) { super().merge(pass_min_days: value) }

        it "is #{expected}" do
          expect(common_facts('RedHat', 'RedHat', '9')['pw_data']['pass_min_days_status']).to be expected
        end
      end
    end

    it 'defaults to non-compliant when the setting is missing' do
      allow(Facter::Core::Execution).to receive(:exec).with(commands[:pass_min_days]).and_return('')
      facts = common_facts('RedHat', 'RedHat', '9')
      expect(facts['pw_data']['pass_min_days']).to eq('0')
      expect(facts['pw_data']['pass_min_days_status']).to be true
    end
  end

  describe 'pass_warn_age_status' do
    {
      '0' => true, '6' => true,
      '7' => false, '14' => false, '99' => false
    }.each do |value, expected|
      context "with PASS_WARN_AGE #{value}" do
        let(:login_defs) { super().merge(pass_warn_age: value) }

        it "is #{expected}" do
          expect(common_facts('RedHat', 'RedHat', '9')['pw_data']['pass_warn_age_status']).to be expected
        end
      end
    end
  end

  describe 'pass_max_days_status' do
    { '90' => false, '365' => false, '366' => true, '99999' => true }.each do |value, expected|
      context "with PASS_MAX_DAYS #{value}" do
        let(:login_defs) { super().merge(pass_max_days: value) }

        it "is #{expected}" do
          expect(common_facts('RedHat', 'RedHat', '9')['pw_data']['pass_max_days_status']).to be expected
        end
      end
    end
  end

  describe 'inactive_status' do
    { '-1' => true, '29' => true, '30' => false, '45' => false }.each do |value, expected|
      context "with INACTIVE #{value}" do
        let(:login_defs) { super().merge(inactive: value) }

        it "is #{expected}" do
          expect(common_facts('RedHat', 'RedHat', '9')['pw_data']['inactive_status']).to be expected
        end
      end
    end
  end

  describe 'pw_change_in_future' do
    context 'when every local user has a valid password date' do
      let(:local_users) { { 'alice' => { 'password_date_valid' => true } } }

      it 'is false' do
        expect(common_facts('RedHat', 'RedHat', '9')['pw_data']['pw_change_in_future']).to be false
      end
    end

    context 'when a local user has a password date in the future' do
      let(:local_users) { { 'alice' => { 'password_date_valid' => true }, 'bob' => { 'password_date_valid' => false } } }

      it 'is true' do
        expect(common_facts('RedHat', 'RedHat', '9')['pw_data']['pw_change_in_future']).to be true
      end
    end
  end

  describe 'password date collection' do
    # The block used to be present twice, with the second copy discarding the
    # results of the first.
    it 'reads each login.defs setting exactly once' do
      common_facts('RedHat', 'RedHat', '9')

      %i[pass_max_days pass_min_days pass_warn_age inactive].each do |key|
        expect(Facter::Core::Execution).to have_received(:exec).with(commands[key]).once
      end
    end
  end

  describe 'postfix' do
    it 'uses rpm on RedHat and reports yes when installed' do
      allow(Facter::Core::Execution).to receive(:exec).with(commands[:postfix_rpm]).and_return('postfix-3.5.8-4.el9.x86_64')
      expect(common_facts('RedHat', 'RedHat', '9')['postfix']).to eq('yes')
    end

    it 'reports no when rpm says the package is not installed' do
      allow(Facter::Core::Execution).to receive(:exec).with(commands[:postfix_rpm]).and_return('package postfix is not installed')
      expect(common_facts('RedHat', 'RedHat', '9')['postfix']).to eq('no')
    end

    it 'uses dpkg on Debian' do
      allow(Facter::Core::Execution).to receive(:exec).with(commands[:postfix_dpkg]).and_return('postfix')
      expect(common_facts('Debian', 'Debian', '12')['postfix']).to eq('yes')
      expect(Facter::Core::Execution).to have_received(:exec).with(commands[:postfix_dpkg])
    end

    it 'uses rpm on Suse' do
      allow(Facter::Core::Execution).to receive(:exec).with(commands[:postfix_rpm]).and_return('postfix-3.5.9-150400.1.1.x86_64')
      expect(common_facts('Suse', 'SLES', '15')['postfix']).to eq('yes')
    end

    it 'reports no when the os family runs neither branch' do
      expect(common_facts('Gentoo', 'Gentoo', '2')['postfix']).to eq('no')
    end
  end

  describe 'logrotate_conf' do
    it 'is empty when nothing matches' do
      expect(common_facts('RedHat', 'RedHat', '9')['logrotate_conf']).to eq({})
    end

    it 'parses an entry per file' do
      allow(Facter::Core::Execution).to receive(:exec).with(commands[:logrotate]).and_return(
        "/etc/logrotate.conf:    create 0664 root utmp\n/etc/logrotate.d/wtmp:    create 0644 root root"
      )

      expect(common_facts('RedHat', 'RedHat', '9')['logrotate_conf']).to eq(
        '/etc/logrotate.conf' => { 'action' => 'create', 'mode' => '0664', 'user' => 'root', 'group' => 'utmp' },
        '/etc/logrotate.d/wtmp' => { 'action' => 'create', 'mode' => '0644', 'user' => 'root', 'group' => 'root' }
      )
    end
  end

  describe 'world writable files' do
    it 'is empty when the cronjob output is absent' do
      facts = common_facts('RedHat', 'RedHat', '9')
      expect(facts['world_writable']).to eq([])
      expect(facts['world_writable_count']).to eq(0)
    end

    it 'reads and counts the cronjob output' do
      allow(File).to receive(:exist?).with('/usr/share/cis_security_hardening/data/world-writable-files.txt').and_return(true)
      allow(File).to receive(:read).
        with('/usr/share/cis_security_hardening/data/world-writable-files.txt').
        and_return(+"/tmp/one\r\n/tmp/two\r\n")

      facts = common_facts('RedHat', 'RedHat', '9')
      expect(facts['world_writable']).to eq(['/tmp/one', '/tmp/two'])
      expect(facts['world_writable_count']).to eq(2)
    end
  end

  describe 'efi' do
    it 'is false when /sys/firmware/efi is absent' do
      expect(common_facts('RedHat', 'RedHat', '9')['efi']).to be false
    end

    it 'is true when /sys/firmware/efi is present' do
      allow(File).to receive(:directory?).with('/sys/firmware/efi').and_return(true)
      expect(common_facts('RedHat', 'RedHat', '9')['efi']).to be true
    end
  end

  it 'merges the wlan data into the top level facts' do
    allow(self).to receive(:read_wlan_data).and_return('wlan' => ['wlan0'], 'wlan_status' => 'enabled')

    facts = common_facts('RedHat', 'RedHat', '9')
    expect(facts['wlan']).to eq(['wlan0'])
    expect(facts['wlan_status']).to eq('enabled')
  end
end
