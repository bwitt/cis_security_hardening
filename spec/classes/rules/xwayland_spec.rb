# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]
gdm_options = [true, false]

describe 'cis_security_hardening::rules::xwayland' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      gdm_options.each do |gdm|
        context "on #{os} with enforce = #{enforce} and gdm = #{gdm}" do
          let(:facts) do
            os_facts.merge!(
              cis_security_hardening: { 'gnome_gdm' => gdm }
            )
          end
          let(:params) do
            {
              'enforce' => enforce,
            }
          end

          it {
            is_expected.to compile

            file = if %w[rocky almalinux redhat centos].include?(os_facts[:os]['name'].downcase)
                     '/etc/gdm/custom.conf'
                   else
                     '/etc/gdm3/custom.conf'
                   end

            if enforce && gdm
              is_expected.to contain_file_line('gdm waylandenable').
                with(
                  'path'               => file,
                  'line'               => 'WaylandEnable=false',
                  'match'              => '^\s*#?\s*WaylandEnable\s*=',
                  'append_on_no_match' => true,
                  'after'              => '^\[daemon\]'
                )
            else
              is_expected.not_to contain_file_line('gdm waylandenable')
            end
          }
        end
      end
    end
  end
end
