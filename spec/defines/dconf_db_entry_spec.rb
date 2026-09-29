# frozen_string_literal: true

require 'spec_helper'

describe 'cis_security_hardening::dconf_db_entry' do
  on_supported_os.each do |os, os_facts|
    context "on #{os} with settings and locks" do
      let(:title) { '01-lock-enabled' }
      let(:facts) { os_facts }
      let(:params) do
        {
          'db'       => 'local',
          'settings' => { 'org/gnome/desktop/screensaver' => { 'lock-enabled' => 'true' } },
          'locks'    => ['/org/gnome/desktop/screensaver/lock-enabled'],
        }
      end

      it {
        is_expected.to compile

        is_expected.to contain_file('/etc/dconf/db/local.d').
          with(
            'ensure'  => 'directory',
            'mode'    => '0755',
            'purge'   => true,
            'recurse' => true,
            'force'   => true
          )

        is_expected.to contain_file('/etc/dconf/db/local.d/locks').
          with(
            'ensure'  => 'directory',
            'mode'    => '0755',
            'purge'   => true,
            'recurse' => true
          )

        is_expected.to contain_dconf__db_keyfile('01-lock-enabled').
          with(
            'parent_db' => '/etc/dconf/db/local.d',
            'filename'  => '01-lock-enabled'
          )

        is_expected.to contain_dconf__db_locks('01-lock-enabled').
          with(
            'parent_db' => '/etc/dconf/db/local.d',
            'filename'  => '01-lock-enabled'
          )

        is_expected.to contain_file('/etc/dconf/db/local.d/01-lock-enabled')
        is_expected.to contain_file('/etc/dconf/db/local.d/locks/01-lock-enabled')
      }
    end

    context "on #{os} with settings only" do
      let(:title) { '00-settings-only' }
      let(:facts) { os_facts }
      let(:params) do
        {
          'db'       => 'local',
          'settings' => { 'org/gnome/desktop/screensaver' => { 'lock-enabled' => 'true' } },
        }
      end

      it {
        is_expected.to compile
        is_expected.to contain_dconf__db_keyfile('00-settings-only')
        is_expected.not_to contain_dconf__db_locks('00-settings-only')
      }
    end

    context "on #{os} sharing one database with a second entry" do
      let(:title) { '01-first' }
      let(:facts) { os_facts }
      let(:params) do
        {
          'db'       => 'local',
          'settings' => { 'org/gnome/desktop/screensaver' => { 'lock-enabled' => 'true' } },
          'locks'    => ['/org/gnome/desktop/screensaver/lock-enabled'],
        }
      end
      let(:pre_condition) do
        <<~PP
          cis_security_hardening::dconf_db_entry { '02-second':
            db       => 'local',
            settings => { 'org/gnome/desktop/session' => { 'idle-delay' => 'uint32 900' } },
            locks    => ['/org/gnome/desktop/session/idle-delay'],
          }
        PP
      end

      it {
        is_expected.to compile
        is_expected.to contain_file('/etc/dconf/db/local.d')
        is_expected.to contain_file('/etc/dconf/db/local.d/01-first')
        is_expected.to contain_file('/etc/dconf/db/local.d/02-second')
        is_expected.to contain_file('/etc/dconf/db/local.d/locks/01-first')
        is_expected.to contain_file('/etc/dconf/db/local.d/locks/02-second')
      }
    end
  end
end
