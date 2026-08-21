# frozen_string_literal: true

require 'spec_helper'
require 'facter/cis_security_hardening/utils/read_dot_file_status'

describe 'read_dot_file_status' do
  let(:users) { { 'alice' => '/home/alice' } }

  before do
    allow(File).to receive(:directory?).with('/home/alice').and_return(true)
    allow(Etc).to receive(:getpwnam).with('alice').and_return(Struct.new(:gid).new(1000))
    allow(Etc).to receive(:getgrgid).with(1000).and_return(Struct.new(:name).new('alice'))

    allow(File).to receive(:file?).and_return(true)
    allow(File).to receive(:symlink?).and_return(false)

    stat_ok      = instance_double(File::Stat, uid: 1000, gid: 1000, mode: 0o100644)
    stat_history = instance_double(File::Stat, uid: 1000, gid: 1000, mode: 0o100644)
    stat_netrc   = instance_double(File::Stat, uid: 1000, gid: 1000, mode: 0o100644)
    stat_loose   = instance_double(File::Stat, uid: 1000, gid: 1000, mode: 0o100666)
    stat_owner   = instance_double(File::Stat, uid: 9999, gid: 1000, mode: 0o100644)

    allow(Etc).to receive(:getpwuid).with(1000).and_return(Struct.new(:name).new('alice'))
    allow(Etc).to receive(:getpwuid).with(9999).and_return(Struct.new(:name).new('someoneelse'))
    allow(Etc).to receive(:getgrgid).with(1000).and_return(Struct.new(:name).new('alice'))

    allow(Dir).to receive(:glob).with('/home/alice/.*').and_return(
      [
        '/home/alice/.bashrc',
        '/home/alice/.bash_history',
        '/home/alice/.netrc',
        '/home/alice/.forward',
        '/home/alice/.rhosts',
        '/home/alice/.loosefile',
        '/home/alice/.wrongowner',
      ]
    )
    allow(File).to receive(:stat).with('/home/alice/.bashrc').and_return(stat_ok)
    allow(File).to receive(:stat).with('/home/alice/.bash_history').and_return(stat_history)
    allow(File).to receive(:stat).with('/home/alice/.netrc').and_return(stat_netrc)
    allow(File).to receive(:stat).with('/home/alice/.loosefile').and_return(stat_loose)
    allow(File).to receive(:stat).with('/home/alice/.wrongowner').and_return(stat_owner)
  end

  it 'flags .forward and .rhosts as alert-only, without inspecting their permissions' do
    result = read_dot_file_status(users)
    expect(result['dotfiles_alert_only']).to contain_exactly('/home/alice/.forward', '/home/alice/.rhosts')
  end

  it 'flags .netrc and .bash_history with excess permissions under the strict mask' do
    result = read_dot_file_status(users)
    # .bash_history and .netrc above are 0644, which trips the 0177 strict mask (group/other read bits)
    expect(result['dotfiles_strict_perm']).to contain_exactly('/home/alice/.bash_history', '/home/alice/.netrc')
  end

  it 'flags an ordinary dotfile with excess permissions under the moderate mask' do
    result = read_dot_file_status(users)
    expect(result['dotfiles_moderate_perm']).to include('/home/alice/.loosefile')
  end

  it 'does not flag an ordinary dotfile that is already within the moderate mask' do
    result = read_dot_file_status(users)
    expect(result['dotfiles_moderate_perm']).not_to include('/home/alice/.bashrc')
  end

  it 'flags a dotfile whose owner does not match the user' do
    result = read_dot_file_status(users)
    expect(result['dotfiles_wrong_owner']).to eq('/home/alice/.wrongowner' => 'alice')
  end

  context 'with a home directory shared by two users' do
    let(:shared_users) do
      {
        'shareduser1' => '/home/shared',
        'shareduser2' => '/home/shared',
      }
    end

    before do
      allow(File).to receive(:directory?).with('/home/shared').and_return(true)
      allow(Etc).to receive(:getpwnam).with('shareduser1').and_return(Struct.new(:gid).new(2000))
      allow(Etc).to receive(:getpwnam).with('shareduser2').and_return(Struct.new(:gid).new(2001))
      allow(Etc).to receive(:getgrgid).with(2000).and_return(Struct.new(:name).new('shareduser1'))
      allow(Etc).to receive(:getgrgid).with(2001).and_return(Struct.new(:name).new('shareduser2'))

      allow(File).to receive(:file?).with('/home/shared/.bash_history').and_return(true)
      allow(File).to receive(:symlink?).with('/home/shared/.bash_history').and_return(false)
      stat_shared = instance_double(File::Stat, uid: 0, gid: 0, mode: 0o100644)
      allow(File).to receive(:stat).with('/home/shared/.bash_history').and_return(stat_shared)
      allow(Dir).to receive(:glob).with('/home/shared/.*').and_return(['/home/shared/.bash_history'])
    end

    it 'globs the shared home exactly once (not once per sharing user)' do
      read_dot_file_status(shared_users)
      expect(Dir).to have_received(:glob).with('/home/shared/.*').once
    end

    it 'reports the shared dotfile via dotfiles_shared instead of guessing an owner (regression: previously duplicate array entries that crashed the catalog compile with a duplicate Exec declaration, same bug class fixed in passwd_gid_exists.pp / PR #98 / ITCPE-722)' do
      result = read_dot_file_status(shared_users)
      expect(result['dotfiles_shared']).to eq(['/home/shared/.bash_history'])
      expect(result['dotfiles_wrong_owner']).not_to have_key('/home/shared/.bash_history')
    end

    it 'still flags the shared dotfile for excess permissions exactly once' do
      result = read_dot_file_status(shared_users)
      expect(result['dotfiles_strict_perm']).to eq(['/home/shared/.bash_history'])
    end
  end

  context 'TOCTOU handling' do
    let(:toctou_users) { { 'alice' => '/home/alice' } }

    before do
      allow(File).to receive(:directory?).with('/home/alice').and_return(true)
      allow(Etc).to receive(:getpwnam).with('alice').and_return(Struct.new(:gid).new(1000))
      allow(Etc).to receive(:getgrgid).with(1000).and_return(Struct.new(:name).new('alice'))
      allow(Dir).to receive(:glob).with('/home/alice/.*').and_return(['/home/alice/.vanishing'])
      allow(File).to receive(:file?).with('/home/alice/.vanishing').and_return(true)
      allow(File).to receive(:symlink?).with('/home/alice/.vanishing').and_return(false)
    end

    it 'skips a file that vanishes between the existence check and stat, instead of raising' do
      allow(File).to receive(:stat).with('/home/alice/.vanishing').and_raise(Errno::ENOENT)
      expect { read_dot_file_status(toctou_users) }.not_to raise_error
      result = read_dot_file_status(toctou_users)
      expect(result['dotfiles_strict_perm']).to be_empty
      expect(result['dotfiles_moderate_perm']).to be_empty
    end
  end
end
