# frozen_string_literal: true

require 'etc'

# for each local interactive user, categorize top-level dotfiles (no recursion
# into subdirectories) in their home directory for the dot-files access
# control: .forward/.rhosts are alert-only (CIS's own remediation is "list for
# manual deletion", not an automatic action); .netrc/.bash_history need strict
# permissions (0600 or more restrictive); every other dotfile needs moderate
# permissions (0644 or more restrictive); all dotfiles are ownership-checked
def read_dot_file_status(local_interactive_users)
  alert_only = []
  strict_perm_files = []
  moderate_perm_files = []
  wrong_owner = {}
  wrong_group = {}

  local_interactive_users.each do |user, home|
    next unless File.directory?(home)

    primary_group = begin
      Etc.getgrgid(Etc.getpwnam(user).gid).name
    rescue ArgumentError
      nil
    end

    Dir.glob(File.join(home, '.*')).each do |path|
      next unless File.file?(path) && !File.symlink?(path)

      base = File.basename(path)

      if ['.forward', '.rhosts'].include?(base)
        alert_only.push(path)
        next
      end

      stat = File.stat(path)
      owner = begin
        Etc.getpwuid(stat.uid).name
      rescue ArgumentError
        nil
      end
      group = begin
        Etc.getgrgid(stat.gid).name
      rescue ArgumentError
        nil
      end
      wrong_owner[path] = user if owner != user
      wrong_group[path] = primary_group if primary_group && group != primary_group

      if ['.netrc', '.bash_history'].include?(base)
        strict_perm_files.push(path) if (stat.mode & 0o177) != 0
      elsif (stat.mode & 0o133) != 0
        moderate_perm_files.push(path)
      end
    end
  end

  {
    'dotfiles_alert_only'    => alert_only,
    'dotfiles_strict_perm'   => strict_perm_files,
    'dotfiles_moderate_perm' => moderate_perm_files,
    'dotfiles_wrong_owner'   => wrong_owner,
    'dotfiles_wrong_group'   => wrong_group,
  }
end
