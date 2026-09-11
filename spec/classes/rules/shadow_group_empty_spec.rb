# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::shadow_group_empty' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) { os_facts }
        let(:params) do
          {
            'enforce' => enforce,
          }
        end

        it {
          is_expected.to compile

          if enforce
            is_expected.to contain_exec('remove all members from the shadow group').
              with(
                'command' => 'sed -ri \'s/(^shadow:[^:]*:[^:]*:)([^:]+$)/\1/\' /etc/group',
                'path'    => ['/bin', '/usr/bin'],
                'onlyif'  => 'test -n "$(awk -F: \'($1=="shadow") {print $NF}\' /etc/group)"'
              )
          else
            is_expected.not_to contain_exec('remove all members from the shadow group')
          end
        }
      end
    end
  end
end
