# frozen_string_literal: true

require 'spec_helper'
require 'facter/cis_security_hardening/utils/read_canonical_homes'

describe 'read_canonical_homes' do
  it 'reports a missing home directory as not existing, canonical falls back to the raw value' do
    allow(File).to receive(:directory?).with('/home/missing').and_return(false)
    result = read_canonical_homes('missinguser' => '/home/missing')
    expect(result['missinguser']).to eq('home' => '/home/missing', 'exists' => false, 'canonical' => '/home/missing')
  end

  it 'canonicalizes an existing home directory via realpath' do
    allow(File).to receive(:directory?).with('/home/real').and_return(true)
    allow(File).to receive(:realpath).with('/home/real').and_return('/home/real')
    result = read_canonical_homes('user' => '/home/real')
    expect(result['user']).to eq('home' => '/home/real', 'exists' => true, 'canonical' => '/home/real')
  end

  it 'falls back to the raw value when realpath raises (e.g. a broken symlink race)' do
    allow(File).to receive(:directory?).with('/home/racy').and_return(true)
    allow(File).to receive(:realpath).with('/home/racy').and_raise(Errno::ENOENT)
    result = read_canonical_homes('user' => '/home/racy')
    expect(result['user']).to eq('home' => '/home/racy', 'exists' => true, 'canonical' => '/home/racy')
  end

  it 'resolves two differently-formatted paths for the same real directory to the same canonical value' do
    allow(File).to receive(:directory?).with('/home/shared').and_return(true)
    allow(File).to receive(:directory?).with('/home/shared-link').and_return(true)
    allow(File).to receive(:realpath).with('/home/shared').and_return('/home/shared')
    allow(File).to receive(:realpath).with('/home/shared-link').and_return('/home/shared')

    result = read_canonical_homes('user1' => '/home/shared', 'user2' => '/home/shared-link')
    expect(result['user1']['canonical']).to eq(result['user2']['canonical'])
  end
end
