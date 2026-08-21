# frozen_string_literal: true

# enumerate local interactive users (login shell present in /etc/shells,
# excluding any nologin-style shell) and their home directory, per /etc/passwd
def read_local_interactive_users
  valid_shells = if File.exist?('/etc/shells')
                   File.readlines('/etc/shells').map(&:strip).reject do |line|
                     line.empty? || line.start_with?('#') || line.end_with?('nologin')
                   end
                 else
                   []
                 end

  users = {}
  File.readlines('/etc/passwd').each do |line|
    fields = line.strip.split(':')
    user  = fields[0]
    shell = fields[6]
    home  = fields[5]
    next if user.nil? || shell.nil? || home.nil?
    next unless valid_shells.include?(shell)

    users[user] = home
  end
  users
end
