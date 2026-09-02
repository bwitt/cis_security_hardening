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
    # An empty (but present) shell field is intentionally excluded, matching the official
    # CIS audit's own intent that a local interactive user has a real login shell. Ruby's
    # split(':') with no limit drops a trailing empty field entirely, so a passwd line
    # ending in an empty shell (e.g. "user:x:1000:1000:comment:/home/user:") yields
    # fields[6] == nil here, not "" -- the nil guard below is what actually excludes it,
    # not a lookup miss against valid_shells. Verified directly against a real synthetic
    # /etc/passwd entry with a blank shell field (see read_local_interactive_users_spec.rb).
    shell = fields[6]
    home  = fields[5]
    next if user.nil? || shell.nil? || home.nil?
    next unless valid_shells.include?(shell)

    users[user] = home
  end
  users
end
