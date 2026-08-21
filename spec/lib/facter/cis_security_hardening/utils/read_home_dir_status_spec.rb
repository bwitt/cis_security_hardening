# frozen_string_literal: true

require 'spec_helper'
require 'facter/cis_security_hardening/utils/read_home_dir_status'

describe 'read_home_dir_status' do
  let(:users) do
    {
      'missinguser' => '/home/missinguser',
      'wrongowner'  => '/home/wrongowner',
      'looseperms'  => '/home/looseperms',
      'gooduser'    => '/home/gooduser',
    }
  end

  before do
    allow(File).to receive(:directory?).and_return(true)
    allow(File).to receive(:directory?).with('/home/missinguser').and_return(false)

    stat_wrongowner = instance_double(File::Stat, uid: 9999, mode: 0o040750)
    stat_looseperms = instance_double(File::Stat, uid: 1002, mode: 0o040777)
    stat_gooduser   = instance_double(File::Stat, uid: 1001, mode: 0o040750)

    allow(File).to receive(:stat).with('/home/wrongowner').and_return(stat_wrongowner)
    allow(File).to receive(:stat).with('/home/looseperms').and_return(stat_looseperms)
    allow(File).to receive(:stat).with('/home/gooduser').and_return(stat_gooduser)

    allow(Etc).to receive(:getpwuid).with(9999).and_return(Struct.new(:name).new('someoneelse'))
    allow(Etc).to receive(:getpwuid).with(1001).and_return(Struct.new(:name).new('gooduser'))
    allow(Etc).to receive(:getpwuid).with(1002).and_return(Struct.new(:name).new('looseperms'))
  end

  it 'flags a user with no home directory' do
    expect(read_home_dir_status(users)['missing_home_dir']).to include('missinguser')
  end

  it 'flags a home directory whose owner does not match the username' do
    expect(read_home_dir_status(users)['home_dir_wrong_owner']).to eq('/home/wrongowner' => 'wrongowner')
  end

  it 'flags a home directory with group-write or other-rwx bits set' do
    expect(read_home_dir_status(users)['home_dir_excess_perms']).to include('/home/looseperms')
  end

  it 'does not flag a correctly owned, correctly permissioned home directory' do
    status = read_home_dir_status(users)
    expect(status['home_dir_excess_perms']).not_to include('/home/gooduser')
    expect(status['home_dir_wrong_owner']).not_to have_key('/home/gooduser')
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
      stat_shared = instance_double(File::Stat, uid: 0, mode: 0o040777)
      allow(File).to receive(:stat).with('/home/shared').and_return(stat_shared)
    end

    it 'reports the shared home exactly once, not once per sharing user' do
      status = read_home_dir_status(shared_users)
      expect(status['home_dir_shared']).to eq(['/home/shared'])
    end

    it 'reports excess permissions exactly once, not once per sharing user (regression: previously a duplicate array entry that crashed the catalog compile with a duplicate Exec declaration, same bug class fixed in passwd_gid_exists.pp / PR #98 / ITCPE-722)' do
      status = read_home_dir_status(shared_users)
      expect(status['home_dir_excess_perms']).to eq(['/home/shared'])
    end

    it 'does not guess an owner for the shared home' do
      status = read_home_dir_status(shared_users)
      expect(status['home_dir_wrong_owner']).not_to have_key('/home/shared')
    end
  end
end
