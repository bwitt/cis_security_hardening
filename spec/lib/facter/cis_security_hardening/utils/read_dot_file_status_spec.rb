# frozen_string_literal: true

require 'spec_helper'
require 'facter/cis_security_hardening/utils/read_canonical_homes'
require 'facter/cis_security_hardening/utils/read_dot_file_status'

describe 'read_dot_file_status' do
  let(:users) { { 'alice' => '/home/alice' } }

  before do
    allow(File).to receive(:directory?).with('/home/alice').and_return(true)
    allow(File).to receive(:realpath).with('/home/alice').and_return('/home/alice')
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
      allow(File).to receive(:realpath).with('/home/shared').and_return('/home/shared')
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
      allow(File).to receive(:realpath).with('/home/alice').and_return('/home/alice')
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

  context "when the owning user's primary group can't be resolved via NSS" do
    let(:unresolvable_users) { { 'ghost' => '/home/ghost' } }

    before do
      allow(File).to receive(:directory?).with('/home/ghost').and_return(true)
      allow(File).to receive(:realpath).with('/home/ghost').and_return('/home/ghost')
      allow(Etc).to receive(:getpwnam).with('ghost').and_raise(ArgumentError)
      allow(Dir).to receive(:glob).with('/home/ghost/.*').and_return(['/home/ghost/.bashrc'])
      allow(File).to receive(:file?).with('/home/ghost/.bashrc').and_return(true)
      allow(File).to receive(:symlink?).with('/home/ghost/.bashrc').and_return(false)
      stat_ghost = instance_double(File::Stat, uid: 1234, gid: 1234, mode: 0o100644)
      allow(File).to receive(:stat).with('/home/ghost/.bashrc').and_return(stat_ghost)
      allow(Etc).to receive(:getpwuid).with(1234).and_return(Struct.new(:name).new('ghost'))
      allow(Etc).to receive(:getgrgid).with(1234).and_return(Struct.new(:name).new('ghost'))
    end

    it 'reports the dotfile via dotfiles_group_unresolvable instead of silently skipping the group check' do
      result = read_dot_file_status(unresolvable_users)
      expect(result['dotfiles_group_unresolvable']).to eq(['/home/ghost/.bashrc'])
      expect(result['dotfiles_wrong_group']).not_to have_key('/home/ghost/.bashrc')
    end
  end

  context 'when .forward or .rhosts is itself a symlink' do
    let(:symlink_users) { { 'bob' => '/home/bob' } }

    before do
      allow(File).to receive(:directory?).with('/home/bob').and_return(true)
      allow(File).to receive(:realpath).with('/home/bob').and_return('/home/bob')
      allow(Etc).to receive(:getpwnam).with('bob').and_return(Struct.new(:gid).new(1000))
      allow(Etc).to receive(:getgrgid).with(1000).and_return(Struct.new(:name).new('bob'))
      allow(Dir).to receive(:glob).with('/home/bob/.*').and_return(['/home/bob/.forward'])
      # a symlinked .forward: File.file? follows the link (true), but so does
      # File.symlink? (true) -- regression test for the bug where the old
      # file?/symlink? guard ran *before* the .forward/.rhosts basename
      # check, silently excluding a symlinked .forward from the alert
      allow(File).to receive(:file?).with('/home/bob/.forward').and_return(true)
      allow(File).to receive(:symlink?).with('/home/bob/.forward').and_return(true)
    end

    it 'still flags a symlinked .forward as alert-only' do
      result = read_dot_file_status(symlink_users)
      expect(result['dotfiles_alert_only']).to eq(['/home/bob/.forward'])
    end
  end

  context 'with a home directory shared by two users via genuinely different raw paths that resolve to the same real directory' do
    # unlike a trailing-slash variant (which File.join normalizes away before
    # Dir.glob even sees it), a symlink-style alias produces two genuinely
    # different glob targets for the same real directory -- this is what
    # actually distinguishes canonical-path dedup from raw-string dedup
    let(:aliased_users) do
      {
        'aliaseduser1' => '/home/aliased',
        'aliaseduser2' => '/home/aliased-link',
      }
    end

    before do
      allow(File).to receive(:directory?).with('/home/aliased').and_return(true)
      allow(File).to receive(:directory?).with('/home/aliased-link').and_return(true)
      allow(File).to receive(:realpath).with('/home/aliased').and_return('/home/aliased')
      allow(File).to receive(:realpath).with('/home/aliased-link').and_return('/home/aliased')
      allow(Etc).to receive(:getpwnam).with('aliaseduser1').and_return(Struct.new(:gid).new(3000))
      allow(Etc).to receive(:getpwnam).with('aliaseduser2').and_return(Struct.new(:gid).new(3001))
      allow(Etc).to receive(:getgrgid).with(3000).and_return(Struct.new(:name).new('aliaseduser1'))
      allow(Etc).to receive(:getgrgid).with(3001).and_return(Struct.new(:name).new('aliaseduser2'))

      allow(Dir).to receive(:glob).with('/home/aliased/.*').and_return(['/home/aliased/.bash_history'])
      allow(Dir).to receive(:glob).with('/home/aliased-link/.*').and_return(['/home/aliased-link/.bash_history'])
      allow(File).to receive(:file?).with('/home/aliased/.bash_history').and_return(true)
      allow(File).to receive(:symlink?).with('/home/aliased/.bash_history').and_return(false)
      stat_shared = instance_double(File::Stat, uid: 0, gid: 0, mode: 0o100644)
      allow(File).to receive(:stat).with('/home/aliased/.bash_history').and_return(stat_shared)
    end

    it 'globs only the first-seen alias, not both (regression: seen-homes dedup previously keyed on the raw string, not the canonical path)' do
      read_dot_file_status(aliased_users)
      expect(Dir).not_to have_received(:glob).with('/home/aliased-link/.*')
    end

    it 'reports the shared dotfile exactly once, under the first-seen alias' do
      result = read_dot_file_status(aliased_users)
      expect(result['dotfiles_shared']).to eq(['/home/aliased/.bash_history'])
    end
  end
end
