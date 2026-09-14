# frozen_string_literal: true

require 'spec_helper'
require 'facter/cis_security_hardening/utils/read_canonical_homes'
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
    allow(File).to receive(:realpath) { |path| path }

    stat_wrongowner = instance_double(File::Stat, uid: 9999, mode: 0o040750)
    stat_looseperms = instance_double(File::Stat, uid: 1002, mode: 0o040777)
    stat_gooduser   = instance_double(File::Stat, uid: 1001, mode: 0o040750)

    allow(File).to receive(:stat).with('/home/wrongowner').and_return(stat_wrongowner)
    allow(File).to receive(:stat).with('/home/looseperms').and_return(stat_looseperms)
    allow(File).to receive(:stat).with('/home/gooduser').and_return(stat_gooduser)

    allow(Etc).to receive(:getpwnam).with('wrongowner').and_return(Struct.new(:uid).new(1000))
    allow(Etc).to receive(:getpwnam).with('gooduser').and_return(Struct.new(:uid).new(1001))
    allow(Etc).to receive(:getpwnam).with('looseperms').and_return(Struct.new(:uid).new(1002))
  end

  context 'when the home directory vanishes between the existence check and stat (TOCTOU)' do
    let(:toctou_users) { { 'vanishing' => '/home/vanishing' } }

    before do
      allow(File).to receive(:directory?).with('/home/vanishing').and_return(true)
      allow(File).to receive(:realpath).with('/home/vanishing').and_return('/home/vanishing')
      allow(File).to receive(:stat).with('/home/vanishing').and_raise(Errno::ENOENT)
    end

    it 'skips a home directory that vanishes between the existence check and stat, instead of raising' do
      expect { read_home_dir_status(read_canonical_homes(toctou_users)) }.not_to raise_error
      status = read_home_dir_status(read_canonical_homes(toctou_users))
      expect(status['home_dir_wrong_owner']).not_to have_key('/home/vanishing')
      expect(status['home_dir_excess_perms']).not_to include('/home/vanishing')
    end
  end

  it 'flags a user with no home directory' do
    expect(read_home_dir_status(read_canonical_homes(users))['missing_home_dir']).to include('missinguser')
  end

  it 'flags a home directory whose owner does not match the username' do
    expect(read_home_dir_status(read_canonical_homes(users))['home_dir_wrong_owner']).to eq('/home/wrongowner' => 'wrongowner')
  end

  it 'flags a home directory with group-write or other-rwx bits set' do
    expect(read_home_dir_status(read_canonical_homes(users))['home_dir_excess_perms']).to include('/home/looseperms')
  end

  it 'does not flag a correctly owned, correctly permissioned home directory' do
    status = read_home_dir_status(read_canonical_homes(users))
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
      allow(File).to receive(:realpath).with('/home/shared').and_return('/home/shared')
      stat_shared = instance_double(File::Stat, uid: 0, mode: 0o040777)
      allow(File).to receive(:stat).with('/home/shared').and_return(stat_shared)
    end

    it 'reports the shared home exactly once, not once per sharing user' do
      status = read_home_dir_status(read_canonical_homes(shared_users))
      expect(status['home_dir_shared']).to eq(['/home/shared'])
    end

    it 'reports excess permissions exactly once, not once per sharing user (regression: previously a duplicate array entry that crashed the catalog compile with a duplicate Exec declaration, same bug class fixed in passwd_gid_exists.pp / PR #98 / ITCPE-722)' do
      status = read_home_dir_status(read_canonical_homes(shared_users))
      expect(status['home_dir_excess_perms']).to eq(['/home/shared'])
    end

    it 'does not guess an owner for the shared home' do
      status = read_home_dir_status(read_canonical_homes(shared_users))
      expect(status['home_dir_wrong_owner']).not_to have_key('/home/shared')
    end
  end

  context 'with a home directory shared by two users via differently-formatted paths that resolve to the same real directory' do
    let(:aliased_users) do
      {
        'aliaseduser1' => '/home/aliased',
        'aliaseduser2' => '/home/aliased/',
      }
    end

    before do
      allow(File).to receive(:directory?).with('/home/aliased').and_return(true)
      allow(File).to receive(:directory?).with('/home/aliased/').and_return(true)
      # both literal strings resolve to the same real path -- this is exactly
      # what raw string-equality tallying would miss
      allow(File).to receive(:realpath).with('/home/aliased').and_return('/home/aliased')
      allow(File).to receive(:realpath).with('/home/aliased/').and_return('/home/aliased')
      stat_aliased = instance_double(File::Stat, uid: 0, mode: 0o040750)
      allow(File).to receive(:stat).with('/home/aliased').and_return(stat_aliased)
      allow(File).to receive(:stat).with('/home/aliased/').and_return(stat_aliased)
    end

    it 'reports the shared home exactly once via its canonical path, not once per raw alias (regression: previously both raw strings were reported as separate entries, which would have declared two Puppet resources for the same real directory)' do
      status = read_home_dir_status(read_canonical_homes(aliased_users))
      expect(status['home_dir_shared']).to eq(['/home/aliased'])
      expect(status['home_dir_wrong_owner']).to be_empty
    end
  end

  context 'when two users share a UID' do
    let(:uid_collision_users) do
      {
        'alice'  => '/home/alice',
        'alice2' => '/home/alice2',
      }
    end

    before do
      allow(File).to receive(:directory?).with('/home/alice').and_return(true)
      allow(File).to receive(:directory?).with('/home/alice2').and_return(true)
      allow(File).to receive(:realpath).with('/home/alice').and_return('/home/alice')
      allow(File).to receive(:realpath).with('/home/alice2').and_return('/home/alice2')

      stat_alice  = instance_double(File::Stat, uid: 2000, mode: 0o040750)
      stat_alice2 = instance_double(File::Stat, uid: 2000, mode: 0o040750)
      allow(File).to receive(:stat).with('/home/alice').and_return(stat_alice)
      allow(File).to receive(:stat).with('/home/alice2').and_return(stat_alice2)

      allow(Etc).to receive(:getpwnam).with('alice').and_return(Struct.new(:uid).new(2000))
      allow(Etc).to receive(:getpwnam).with('alice2').and_return(Struct.new(:uid).new(2000))
    end

    it 'does not flag either home as wrong-owner (regression: a reverse uid->name NSS lookup resolves uid 2000 to one canonical name, e.g. "alice", causing a false-positive mismatch against the literal username "alice2" even though alice2 genuinely owns uid 2000)' do
      status = read_home_dir_status(read_canonical_homes(uid_collision_users))
      expect(status['home_dir_wrong_owner']).not_to have_key('/home/alice2')
      expect(status['home_dir_wrong_owner']).not_to have_key('/home/alice')
    end
  end

  context 'with a home directory shared by two users, where the first-encountered alias fails to stat' do
    let(:flaky_aliased_users) do
      {
        'flakyuser'  => '/home/flaky-link',
        'stableuser' => '/home/flaky',
      }
    end

    before do
      allow(File).to receive(:directory?).with('/home/flaky-link').and_return(true)
      allow(File).to receive(:directory?).with('/home/flaky').and_return(true)
      allow(File).to receive(:realpath).with('/home/flaky-link').and_return('/home/flaky')
      allow(File).to receive(:realpath).with('/home/flaky').and_return('/home/flaky')

      allow(File).to receive(:stat).with('/home/flaky-link').and_raise(Errno::ENOENT)
      stat_flaky = instance_double(File::Stat, uid: 0, mode: 0o040777)
      allow(File).to receive(:stat).with('/home/flaky').and_return(stat_flaky)
    end

    it 'still reports the shared home via the second, working alias (regression: previously the canonical path was marked "seen" before its stat was confirmed to succeed, permanently skipping a reachable alias processed later)' do
      status = read_home_dir_status(read_canonical_homes(flaky_aliased_users))
      expect(status['home_dir_shared']).to eq(['/home/flaky'])
      expect(status['home_dir_excess_perms']).to eq(['/home/flaky'])
    end
  end
end
