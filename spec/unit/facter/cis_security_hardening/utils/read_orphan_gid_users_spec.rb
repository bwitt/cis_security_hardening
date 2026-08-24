# frozen_string_literal: true

require 'spec_helper'
require 'facter/cis_security_hardening/utils/read_orphan_gid_users'

describe 'read_orphan_gid_users' do
  before do
    allow(File).to receive(:readlines).with('/etc/group').and_return(
      [
        "root:x:0:\n",
        "sudo:x:27:\n",
      ]
    )
    allow(File).to receive(:readlines).with('/etc/passwd').and_return(
      [
        "root:x:0:0:root:/root:/bin/bash\n",
        "gooduser:x:1000:27::/home/gooduser:/bin/bash\n",
        "orphaneduser:x:1001:9999::/home/orphaneduser:/bin/bash\n",
      ]
    )
  end

  it 'returns only accounts whose GID has no matching /etc/group entry' do
    expect(read_orphan_gid_users).to eq(['orphaneduser'])
  end

  it 'excludes accounts whose GID exists in /etc/group' do
    expect(read_orphan_gid_users).not_to include('root', 'gooduser')
  end

  context 'when two /etc/passwd lines share a username and both are orphaned' do
    before do
      allow(File).to receive(:readlines).with('/etc/passwd').and_return(
        [
          "root:x:0:0:root:/root:/bin/bash\n",
          "dupuser:x:1001:9999::/home/dupuser:/bin/bash\n",
          "dupuser:x:1002:9998::/home/dupuser2:/bin/bash\n",
        ]
      )
    end

    it 'returns the duplicated username only once' do
      expect(read_orphan_gid_users).to eq(['dupuser'])
    end
  end
end
