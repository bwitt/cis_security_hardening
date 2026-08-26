# frozen_string_literal: true

require 'spec_helper'
require 'yaml'

enforce_options = [true, false]

# Mirrors what the class's own `lookup('cis_security_hardening::rules::ufw_install::enforce', ...)`
# resolves to for a given OS, by reading the same real data file hiera.yaml points at — rather than
# hardcoding a duplicate true/false table that could silently drift from the data.
def real_ufw_install_enforce(os_facts)
  params_file = File.expand_path(
    "../../../data/cis/cis_#{os_facts[:os]['name']}_#{os_facts[:os]['release']['major']}_params.yaml", __dir__
  )
  return false unless File.exist?(params_file)

  YAML.load_file(params_file).fetch('cis_security_hardening::rules::ufw_install::enforce', false)
end

describe 'cis_security_hardening::rules::iptables_persistent' do
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

          if enforce && real_ufw_install_enforce(os_facts)
            if os_facts[:os]['family'].casecmp('suse').zero?
              is_expected.to contain_package('iptables-persistent').
                with(
                  'ensure' => 'absent'
                )
            else
              is_expected.to contain_package('iptables-persistent').
                with(
                  'ensure' => 'purged'
                )
            end
          else
            is_expected.not_to contain_package('iptables-persistent')
          end
        }
      end
    end
  end
end
