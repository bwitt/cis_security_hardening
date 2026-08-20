# frozen_string_literal: true

# find accounts in /etc/passwd whose primary GID has no matching entry in /etc/group
def read_orphan_gid_users
  group_gids = File.readlines('/etc/group').filter_map { |line| line.strip.split(':')[2] }.uniq

  orphans = []
  File.readlines('/etc/passwd').each do |line|
    fields = line.strip.split(':')
    user = fields[0]
    gid = fields[3]
    next if user.nil? || gid.nil?

    orphans.push(user) unless group_gids.include?(gid)
  end
  orphans.uniq
end
