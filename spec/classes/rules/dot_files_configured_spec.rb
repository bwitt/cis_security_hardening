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
            is_expected.to contain_exec('restrict dot file permissions (.netrc/.bash_history): /home/alice/.netrc').
              with_command('/bin/chmod u-x,go-rwx /home/alice/.netrc')
            is_expected.to contain_exec('restrict dot file permissions: /home/alice/.loosefile').
              with_command('/bin/chmod u-x,go-wx /home/alice/.loosefile')
            is_expected.to contain_exec('correct dot file owner: /home/alice/.wrongowner').
              with_command('/bin/chown alice /home/alice/.wrongowner')
            is_expected.to contain_exec('correct dot file group: /home/alice/.wronggroup').
              with_command('/bin/chgrp alice /home/alice/.wronggroup')
          else
            is_expected.not_to contain_notify('dot file flagged for manual review: /home/alice/.forward')
            is_expected.not_to contain_exec('restrict dot file permissions (.netrc/.bash_history): /home/alice/.netrc')
          end
        }
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
