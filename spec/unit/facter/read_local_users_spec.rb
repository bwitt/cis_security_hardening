# frozen_string_literal: true

require 'spec_helper'
require_relative '../../../lib/facter/cis_security_hardening/utils/read_local_users'

describe 'read_local_users' do
  # day 20000 of the epoch is 2024-10-04
  let(:today) { Date.new(2024, 10, 4) }

  before do
    allow(Date).to receive(:today).and_return(today)
  end

  def with_shadow(*lines)
    allow(File).to receive(:readlines).with('/etc/shadow').and_return(lines)
  end

  context 'with an account that has aging configured' do
    before { with_shadow('u1:$6$hash:19900:7:90:7:30:21000:') }

    it 'derives the values chage would report' do
      expect(read_local_users['u1']).to eq(
        'last_password_change_days' => 100,
        'password_expires_days' => -10,
        'password_inactive_days' => 30,
        'account_expires_days' => 1000,
        'min_days_between_password_change' => 7,
        'max_days_between_password_change' => 90,
        'warn_days_between_password_change' => 7,
        'password_date_valid' => true
      )
    end
  end

  context 'with an account that never expires' do
    before { with_shadow('u2:$6$hash:19900:0:99999:7:::') }

    it 'reports never rather than a number' do
      result = read_local_users['u2']
      expect(result['password_expires_days']).to eq('never')
      expect(result['password_inactive_days']).to eq('never')
      expect(result['account_expires_days']).to eq('never')
      expect(result['max_days_between_password_change']).to eq(99_999)
    end
  end

  # chage stops printing an expiry date at max = 10000 days, not at the 99999
  # conventionally written to mean "never", and calls the inactive date never
  # at the same point
  context 'around the threshold chage treats as never' do
    it 'still reports a number just below it' do
      with_shadow('u:$6$hash:19900:0:9999:7:30::')
      result = read_local_users['u']
      expect(result['password_expires_days']).to eq(9999 - 100)
      expect(result['password_inactive_days']).to eq(30)
    end

    it 'reports never at the threshold' do
      with_shadow('u:$6$hash:19900:0:10000:7:30::')
      result = read_local_users['u']
      expect(result['password_expires_days']).to eq('never')
      expect(result['password_inactive_days']).to eq('never')
    end

    it 'reports never well above it' do
      with_shadow('u:$6$hash:19900:0:50000:7:30::')
      expect(read_local_users['u']['password_expires_days']).to eq('never')
    end
  end

  context 'with an account flagged for a forced password change' do
    before { with_shadow('u3:$6$hash:0:0:99999:7:::') }

    it 'reports the forced-change state' do
      result = read_local_users['u3']
      expect(result['last_password_change_days']).to eq('password must be changed')
      expect(result['password_expires_days']).to eq('password must be changed')
      expect(result['password_date_valid']).to be_nil
    end
  end

  context 'when selecting accounts' do
    before do
      with_shadow(
        'locked:!:19900:0:99999:7:::',
        'lockedhash:!$6$hash:19900:0:99999:7:::',
        'nologin:*:19900:0:99999:7:::',
        'neverset:!!:19900:0:99999:7:::',
        'passwordless::19900:0:99999:7:::',
        'ok:$6$hash:19900:0:99999:7:::'
      )
    end

    # the regex this replaced, ^[^:]+:[^\!*], skipped ! and * but matched an
    # empty password field, so passwordless accounts stay in scope
    it 'skips locked and nologin accounts but keeps passwordless ones' do
      expect(read_local_users.keys).to eq(%w[passwordless ok])
    end
  end

  context 'with unset aging fields' do
    before { with_shadow('u:$6$hash:19900::::::') }

    # chage reports an unset field as -1, not 0
    it 'reports them as -1' do
      result = read_local_users['u']
      expect(result['min_days_between_password_change']).to eq(-1)
      expect(result['max_days_between_password_change']).to eq(-1)
      expect(result['warn_days_between_password_change']).to eq(-1)
    end
  end

  context 'when /etc/shadow cannot be read' do
    before do
      allow(File).to receive(:readlines).with('/etc/shadow').and_raise(Errno::EACCES)
    end

    it 'returns no users instead of raising' do
      expect(read_local_users).to eq({})
    end
  end
end
