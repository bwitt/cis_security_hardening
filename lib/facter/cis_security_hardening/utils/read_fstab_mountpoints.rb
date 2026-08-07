# frozen_string_literal: true

# read all mountpoints defined in /etc/fstab
def read_fstab_mountpoints
  mountpoints = {}
  if File.exist?('/etc/fstab')
    lines = File.readlines('/etc/fstab')
    lines.each do |line|
      next if %r{^#}.match?(line)

      data = line.split
      next if data.nil? || data.length < 4

      mountpoints[data[1]] = {
        'device' => data[0],
        'fstype' => data[2],
        'mountoptions' => data[3],
      }
    end
  end

  mountpoints
end
