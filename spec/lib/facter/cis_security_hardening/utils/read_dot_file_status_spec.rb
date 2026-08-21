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
end
