# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::dot_files_configured' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'cis_security_hardening' => {
              'accounts' => {
                'dot_file_status' => {
                  'dotfiles_alert_only'    => %w[/home/alice/.forward],
                  'dotfiles_strict_perm'   => %w[/home/alice/.netrc],
                  'dotfiles_moderate_perm' => %w[/home/alice/.loosefile],
                  'dotfiles_wrong_owner'   => { '/home/alice/.wrongowner' => 'alice' },
                  'dotfiles_wrong_group'   => { '/home/alice/.wronggroup' => 'alice' },
                  'dotfiles_shared'        => %w[/home/shared/.bash_history],
                },
              },
            }
          )
        end
        let(:params) { { 'enforce' => enforce } }

        it {
          is_expected.to compile

          if enforce
            is_expected.to contain_notify('dot file flagged for manual review: /home/alice/.forward')
            is_expected.to contain_notify('dot file ownership ambiguous, home directory shared: /home/shared/.bash_history')
            is_expected.to contain_exec('restrict dot file permissions (strict): /home/alice/.netrc').
              with_command('/bin/chmod u-x,go-rwx /home/alice/.netrc')
            is_expected.to contain_exec('restrict dot file permissions (moderate): /home/alice/.loosefile').
              with_command('/bin/chmod u-x,go-wx /home/alice/.loosefile')
            is_expected.to contain_exec('correct dot file owner: /home/alice/.wrongowner').
              with_command('/bin/chown alice /home/alice/.wrongowner')
            is_expected.to contain_exec('correct dot file group: /home/alice/.wronggroup').
              with_command('/bin/chgrp alice /home/alice/.wronggroup')
          else
            is_expected.not_to contain_notify('dot file flagged for manual review: /home/alice/.forward')
            is_expected.not_to contain_notify('dot file ownership ambiguous, home directory shared: /home/shared/.bash_history')
            is_expected.not_to contain_exec('restrict dot file permissions (strict): /home/alice/.netrc')
          end
        }
      end

      context "on #{os} with enforce = #{enforce} and the dot_file_status fact absent" do
        let(:facts) { os_facts }
        let(:params) { { 'enforce' => enforce } }

        it 'compiles cleanly with no resources declared, regardless of enforce' do
          is_expected.to compile
          is_expected.not_to contain_notify(%r{dot file})
          is_expected.not_to contain_exec(%r{dot file})
        end
      end
    end

    context "on #{os} regression: two users sharing one home directory with a shared .bash_history" do
      # A dotfile under a shared home is reported via dotfiles_shared (ownership is ambiguous,
      # alert-only) AND still gets its permissions corrected (that check doesn't depend on which
      # user is "correct"). The fact layer dedupes the path so this declares exactly one Exec for
      # the permission fix, not two (previously a real duplicate-declaration crash -- the same bug
      # class fixed upstream in passwd_gid_exists.pp, PR #98/ITCPE-722).
      let(:facts) do
        os_facts.merge(
          'cis_security_hardening' => {
            'accounts' => {
              'dot_file_status' => {
                'dotfiles_alert_only'    => [],
                'dotfiles_strict_perm'   => %w[/home/shared/.bash_history],
                'dotfiles_moderate_perm' => [],
                'dotfiles_wrong_owner'   => {},
                'dotfiles_wrong_group'   => {},
                'dotfiles_shared'        => %w[/home/shared/.bash_history],
              },
            },
          }
        )
      end
      let(:params) { { 'enforce' => true } }

      it 'declares the permission-fix exec exactly once and alerts on the shared dotfile' do
        is_expected.to compile
        is_expected.to contain_exec('restrict dot file permissions (strict): /home/shared/.bash_history')
        is_expected.to contain_notify('dot file ownership ambiguous, home directory shared: /home/shared/.bash_history')
        is_expected.not_to contain_exec('correct dot file owner: /home/shared/.bash_history')
      end
    end
  end

  context 'when .forward/.rhosts are not automatically deleted' do
    let(:facts) do
      on_supported_os.first[1].merge(
        'cis_security_hardening' => {
          'accounts' => {
            'dot_file_status' => {
              'dotfiles_alert_only'    => %w[/home/alice/.forward],
              'dotfiles_strict_perm'   => [],
              'dotfiles_moderate_perm' => [],
              'dotfiles_wrong_owner'   => {},
              'dotfiles_wrong_group'   => {},
              'dotfiles_shared'        => [],
            },
          },
        }
      )
    end
    let(:params) { { 'enforce' => true } }

    it 'alerts without declaring any file-removal resource' do
      is_expected.to compile
      is_expected.to contain_notify('dot file flagged for manual review: /home/alice/.forward')
      expect(catalogue.resources.map(&:type)).not_to include('File')
    end
  end
end
