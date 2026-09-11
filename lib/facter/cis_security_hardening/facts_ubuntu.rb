# frozen_string_literal: true

require 'facter/cis_security_hardening/utils/check_package_installed'
require 'facter/cis_security_hardening/utils/check_value_string'
require 'facter/cis_security_hardening/utils/read_file_stats'
require 'facter/cis_security_hardening/utils/read_iptables_rules'
require 'facter/cis_security_hardening/utils/read_apparmor_data'
require 'facter/cis_security_hardening/utils/read_system_command_files'
require 'facter/cis_security_hardening/utils/read_pam_pkcs11'
require 'facter/cis_security_hardening/utils/read_invalid_shell_accounts'
require 'facter/cis_security_hardening/utils/read_orphan_gid_users'
require 'facter/cis_security_hardening/utils/read_duplicate_ids'
require 'facter/cis_security_hardening/utils/read_duplicate_names'
require 'facter/cis_security_hardening/utils/read_local_interactive_users'
require 'facter/cis_security_hardening/utils/read_canonical_homes'
require 'facter/cis_security_hardening/utils/read_home_dir_status'
require 'facter/cis_security_hardening/utils/read_dot_file_status'

# gather Ubuntu specific facts
def facts_ubuntu(os, distid, release)
  cis_security_hardening = common_facts(os, distid, release)

  # get apparmor data
  cis_security_hardening[:apparmor] = read_apparmor_data

  # get gnome display manager information
  cis_security_hardening[:gnome_gdm] = File.exist?('/etc/gdm3/greeter.dconf-defaults')

  # get iptables config
  cis_security_hardening['iptables'] = read_iptables_rules('4')
  cis_security_hardening['ip6tables'] = read_iptables_rules('6')

  # get account information
  accounts = {}
  wrong_shell = []
  cmd = "egrep -v \"^/+\" /etc/passwd | awk -F: '($1!=\"root\" && $1!=\"sync\" && $1!=\"shutdown\" && $1!=\"halt\" && $3<1000 && $7!=\"/usr/sbin/nologin\" && $7!=\"/bin/false\") {print}'"
  val = Facter::Core::Execution.exec(cmd)
  unless val.nil? || val.empty?
    val.split("\n").each do |line|
      data = line.split(%r{:})
      wrong_shell.push(data[0])
    end
  end
  accounts['no_shell_nologin'] = wrong_shell
  accounts['no_shell_nologin_count'] = wrong_shell.count
  val = Facter::Core::Execution.exec('grep "^root:" /etc/passwd | cut -f4 -d:')
  accounts['root_gid'] = check_value_string(val, 'none')
  val = Facter::Core::Execution.exec("awk -F: '($2 == \"\" ) { print $1 }' /etc/shadow")
  accounts['empty_password'] = val.nil? || val.empty? ? [] : val.split("\n")
  val = Facter::Core::Execution.exec("awk -F: '($3 == 0 && $1 != \"root\") { print $1 }' /etc/passwd")
  accounts['uid_zero'] = val.nil? || val.empty? ? [] : val.split("\n")
  val = Facter::Core::Execution.exec("awk -F: '($1 !~ /^(root|sync|shutdown|halt|operator)$/ && $4 == \"0\") { print $1 }' /etc/passwd")
  accounts['gid_zero'] = val.nil? || val.empty? ? [] : val.split("\n")
  val = Facter::Core::Execution.exec("awk -F: '($3 == \"0\" && $1 != \"root\") { print $1 }' /etc/group")
  accounts['gid_zero_groups'] = val.nil? || val.empty? ? [] : val.split("\n")
  accounts['no_valid_shell_unlocked'] = read_invalid_shell_accounts
  accounts['orphan_gid_users'] = read_orphan_gid_users
  accounts['duplicate_uids'] = read_duplicate_ids('/etc/passwd', 2, 0)
  accounts['duplicate_usernames'] = read_duplicate_names('/etc/passwd', 0)
  accounts['duplicate_gids'] = read_duplicate_ids('/etc/group', 2, 0)
  accounts['duplicate_groupnames'] = read_duplicate_names('/etc/group', 0)
  local_interactive_users = read_local_interactive_users
  accounts['local_interactive_users'] = local_interactive_users
  canonical_homes = read_canonical_homes(local_interactive_users)
  accounts['home_dir_status'] = read_home_dir_status(canonical_homes)
  accounts['dot_file_status'] = read_dot_file_status(canonical_homes)
  cis_security_hardening['accounts'] = accounts

  # check for x11 packages
  x11 = {}
  pkgs = Facter::Core::Execution.exec('dpkg -l | grep xorg-x1 | awk \'{print $2;}\'')
  x11['installed'] = !(pkgs.nil? || pkgs.empty?)
  cis_security_hardening[:x11] = x11

  # check for apport
  apport = {}
  pkgs = Facter::Core::Execution.exec('dpkg -l | grep apport| awk \'{print $2;}\'')
  apport['installed'] = !(pkgs.nil? || pkgs.empty?)
  cis_security_hardening['apport'] = apport

  aide = {}
  pkgs = Facter::Core::Execution.exec('dpkg -l | grep aide | awk \'{print $2;}\'')
  aide['installed'] = !(pkgs.nil? || pkgs.empty?)
  cis_security_hardening['aide'] = aide

  # check for xdmcp
  cis_security_hardening['xdcmp'] = File.exist?('/etc/gdm3/custom.conf')

  # get system command files
  cis_security_hardening['system_command_files'] = read_system_command_files

  # read pkcs11 config
  cis_security_hardening['pkcs11_config'] = read_pam_pkcs11_conf

  # return results
  cis_security_hardening
end
