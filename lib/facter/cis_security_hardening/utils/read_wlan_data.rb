# frozen_string_literal: true

# read wlan configuration data
def read_wlan_data
  data = {}

  wireless_paths = Dir.glob('/sys/class/net/*').select do |path|
    File.directory?("#{path}/wireless") || File.exist?("#{path}/phy80211")
  end

  if File.exist?('/usr/bin/nmcli')
    val = Facter::Core::Execution.exec('LC_ALL=C /usr/bin/nmcli radio wifi 2>&1').to_s.strip

    # anything besides "enabled" or "disabled" means something is wrong; treat as disabled
    data['wlan_status'] = %w[enabled disabled].include?(val) ? val : 'disabled'
  else
    data['wlan_interfaces'] = wireless_paths.map { |path| File.basename(path) }.sort
    data['wlan_interfaces_count'] = wireless_paths.length
  end

  # keep track of modules for wireless in use so we can block them
  modules = []
  wireless_paths.each do |path|
    module_link = "#{path}/device/driver/module"
    next unless File.exist?(module_link)

    begin
      modules << File.basename(File.realpath(module_link))
    rescue SystemCallError
      next
    end
  end
  data['wlan_modules'] = modules.uniq.sort

  data
end
