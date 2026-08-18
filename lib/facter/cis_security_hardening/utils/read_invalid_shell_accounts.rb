# frozen_string_literal: true

# find non-root accounts with a shell that isn't a valid interactive shell
# (per /etc/shells, excluding nologin-style shells) and that are not already locked
def read_invalid_shell_accounts
  valid_shells = if File.exist?('/etc/shells')
                   File.readlines('/etc/shells').map(&:strip).reject do |line|
                     line.empty? || line.start_with?('#') || line.end_with?('nologin')
                   end
                 else
                   []
                 end

  accounts = []
  File.readlines('/etc/passwd').each do |line|
    fields = line.strip.split(':')
    user = fields[0]
    shell = fields[6]
    next if user.nil? || user == 'root'
    next if valid_shells.include?(shell)

    status = Facter::Core::Execution.exec("passwd -S #{user} 2>/dev/null")
    next if status.nil? || status.empty?

    locked = status.split[1].to_s.start_with?('L')
    accounts.push(user) unless locked
  end
  accounts
end
