# frozen_string_literal: true

require 'spec_helper'
require 'facter/cis_security_hardening/utils/read_invalid_shell_accounts'

describe 'read_invalid_shell_accounts' do
  before do
    allow(File).to receive(:exist?).with('/etc/shells').and_return(true)
    allow(File).to receive(:readlines).with('/etc/shells').and_return(
      [
        "/bin/bash\n",
        "/bin/sh\n",
        "/usr/sbin/nologin\n",
      ]
    )
    allow(File).to receive(:readlines).with('/etc/passwd').and_return(
      [
        "root:x:0:0:root:/root:/bin/bash\n",
        "svcaccount:x:1001:1001::/home/svcaccount:/bin/false\n",
        "lockeduser:x:1002:1002::/home/lockeduser:/bin/false\n",
        "realuser:x:1003:1003::/home/realuser:/bin/bash\n",
      ]
    )
    allow(Facter::Core::Execution).to receive(:exec).
      with('passwd -S svcaccount 2>/dev/null').and_return('svcaccount P 08/18/2026 0 99999 7 -1')
    allow(Facter::Core::Execution).to receive(:exec).
      with('passwd -S lockeduser 2>/dev/null').and_return('lockeduser L 08/18/2026 0 99999 7 -1')
  end

  it 'returns only unlocked accounts with an invalid shell' do
    expect(read_invalid_shell_accounts).to eq(['svcaccount'])
  end

  it 'excludes root regardless of shell' do
    expect(read_invalid_shell_accounts).not_to include('root')
  end

  it 'excludes accounts with a valid shell' do
    expect(read_invalid_shell_accounts).not_to include('realuser')
  end

  it 'excludes accounts with an invalid shell that are already locked' do
    expect(read_invalid_shell_accounts).not_to include('lockeduser')
  end

  context 'when /etc/shells does not exist' do
    before do
      allow(File).to receive(:exist?).with('/etc/shells').and_return(false)
      allow(Facter::Core::Execution).to receive(:exec).
        with('passwd -S realuser 2>/dev/null').and_return('realuser P 08/18/2026 0 99999 7 -1')
    end

    it 'treats every shell as invalid' do
      expect(read_invalid_shell_accounts).to include('svcaccount', 'realuser')
    end
  end
end
