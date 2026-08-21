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
            is_expected.to contain_exec('correct home directory owner: /home/wrongowner').
              with_command('/bin/chown wrongowner /home/wrongowner')
            is_expected.to contain_exec('remove excess home directory permissions: /home/looseperms').
              with_command('/bin/chmod g-w,o-rwx /home/looseperms')
          else
            is_expected.not_to contain_notify('local interactive user has no home directory: missinguser')
            is_expected.not_to contain_exec('correct home directory owner: /home/wrongowner')
            is_expected.not_to contain_exec('remove excess home directory permissions: /home/looseperms')
          end
        }
      end
    end
  end
end
