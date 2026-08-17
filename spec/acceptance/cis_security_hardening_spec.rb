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

    describe 'dev_shm rules' do
      it 'adds exactly one /dev/shm entry to fstab' do
        expect(shell('grep -c "[[:space:]]/dev/shm[[:space:]]" /etc/fstab').stdout.strip).to eq('1')
      end

      %w[nodev nosuid noexec].each do |opt|
        it "sets #{opt} on the /dev/shm fstab entry" do
          expect(shell('grep "[[:space:]]/dev/shm[[:space:]]" /etc/fstab').stdout).to match(%r{[,\s]#{opt}[,\s]})
        end

        it "applies #{opt} to the running /dev/shm mount" do
          expect(shell('findmnt -no OPTIONS /dev/shm').stdout).to match(%r{\b#{opt}\b})
        end
      end

      it 'does not write seclabel where SELinux is inactive' do
        selinux = shell('getenforce 2>/dev/null || true').stdout.strip
        skip 'SELinux is active' unless selinux.empty? || selinux == 'Disabled'
        expect(shell('grep "[[:space:]]/dev/shm[[:space:]]" /etc/fstab').stdout).not_to match(%r{seclabel})
      end
    end

    describe 'tmp_filesystem' do
      it 'writes the tmp.mount unit' do
        expect(file('/etc/systemd/system/tmp.mount')).to be_file
      end

      it 'enables the unit for the next boot' do
        expect(shell('systemctl is-enabled tmp.mount').stdout.strip).to eq('enabled')
      end

      it 'sets the hardening mount options in the unit' do
        opts = shell('grep -E "^Options=" /etc/systemd/system/tmp.mount').stdout
        expect(opts).to match(%r{nosuid})
        expect(opts).to match(%r{nodev})
        expect(opts).to match(%r{noexec})
      end
    end
  end
end
