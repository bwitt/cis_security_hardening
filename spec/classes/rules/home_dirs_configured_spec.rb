# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::home_dirs_configured' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'cis_security_hardening' => {
              'accounts' => {
                'home_dir_status' => {
                  'missing_home_dir'      => %w[missinguser],
                  'home_dir_wrong_owner'  => { '/home/wrongowner' => 'wrongowner' },
                  'home_dir_excess_perms' => %w[/home/looseperms],
                  'home_dir_shared'       => %w[/home/shared],
                },
              },
            }
          )
        end
        let(:params) { { 'enforce' => enforce } }

        it {
          is_expected.to compile

          if enforce
            is_expected.to contain_notify('local interactive user has no home directory: missinguser')
            is_expected.to contain_notify('home directory shared by more than one local interactive user: /home/shared')
            is_expected.to contain_exec('correct home directory owner: /home/wrongowner').
              with_command('/bin/chown wrongowner /home/wrongowner')
            is_expected.to contain_exec('remove excess home directory permissions: /home/looseperms').
              with_command('/bin/chmod g-w,o-rwx /home/looseperms')
          else
            is_expected.not_to contain_notify('local interactive user has no home directory: missinguser')
            is_expected.not_to contain_notify('home directory shared by more than one local interactive user: /home/shared')
            is_expected.not_to contain_exec('correct home directory owner: /home/wrongowner')
            is_expected.not_to contain_exec('remove excess home directory permissions: /home/looseperms')
          end
        }
      end

      context "on #{os} with enforce = #{enforce} and the home_dir_status fact absent" do
        let(:facts) { os_facts }
        let(:params) { { 'enforce' => enforce } }

        it 'compiles cleanly with no resources declared, regardless of enforce' do
          is_expected.to compile
          is_expected.not_to contain_notify(%r{home directory})
          is_expected.not_to contain_exec(%r{home directory})
        end
      end
    end

    context "on #{os} regression: two users sharing one home directory with excess permissions" do
      # A shared home dir is reported via home_dir_shared (ownership is ambiguous, alert-only)
      # AND still gets its excess permissions corrected (that check doesn't depend on which
      # user is "correct"). The fact layer is responsible for deduping the path so this declares
      # exactly one Exec, not two (previously this was a real duplicate-declaration crash --
      # the same bug class fixed upstream in passwd_gid_exists.pp, PR #98/ITCPE-722).
      let(:facts) do
        os_facts.merge(
          'cis_security_hardening' => {
            'accounts' => {
              'home_dir_status' => {
                'missing_home_dir'      => [],
                'home_dir_wrong_owner'  => {},
                'home_dir_excess_perms' => %w[/home/shared],
                'home_dir_shared'       => %w[/home/shared],
              },
            },
          }
        )
      end
      let(:params) { { 'enforce' => true } }

      it 'declares the excess-permissions exec exactly once and alerts on the shared home' do
        is_expected.to compile
        is_expected.to contain_exec('remove excess home directory permissions: /home/shared')
        is_expected.to contain_notify('home directory shared by more than one local interactive user: /home/shared')
        is_expected.not_to contain_exec('correct home directory owner: /home/shared')
      end
    end
  end
end
