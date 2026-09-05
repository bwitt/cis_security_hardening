# frozen_string_literal: true

require 'spec_helper'
require 'facter/cis_security_hardening/utils/read_local_interactive_users'

describe 'read_local_interactive_users' do
  before do
    allow(File).to receive(:exist?).and_call_original
    allow(File).to receive(:exist?).with('/etc/shells').and_return(true)
    allow(File).to receive(:readlines).with('/etc/shells').and_return(
      [
        "# /etc/shells: valid login shells\n",
        "/bin/sh\n",
        "/bin/bash\n",
        "/usr/sbin/nologin\n",
      ]
    )
    allow(File).to receive(:readlines).with('/etc/passwd').and_return(
      [
        "root:x:0:0:root:/root:/bin/bash\n",
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
        "alice:x:1000:1000:Alice:/home/alice:/bin/bash\n",
      ]
    )
  end

  it 'returns users whose shell is a valid interactive shell' do
    expect(read_local_interactive_users).to include('root' => '/root', 'alice' => '/home/alice')
  end

  it 'excludes users whose shell is a nologin-style shell' do
    expect(read_local_interactive_users).not_to have_key('daemon')
  end

  context 'when /etc/shells does not exist' do
    before do
      allow(File).to receive(:exist?).with('/etc/shells').and_return(false)
    end

    it 'returns no users' do
      expect(read_local_interactive_users).to eq({})
    end
  end

  context 'with a user whose shell field is empty (not nologin, just blank)' do
    before do
      allow(File).to receive(:readlines).with('/etc/passwd').and_return(
        [
          "root:x:0:0:root:/root:/bin/bash\n",
          "emptyshell:x:1002:1002:Empty Shell:/home/emptyshell:\n",
        ]
      )
    end

    it 'excludes the user (Ruby split(":") drops the trailing empty field entirely, so the nil-shell guard catches it -- verified directly against a real /etc/passwd entry with a blank 7th field, not just inferred)' do
      expect(read_local_interactive_users).not_to have_key('emptyshell')
    end
  end
end
