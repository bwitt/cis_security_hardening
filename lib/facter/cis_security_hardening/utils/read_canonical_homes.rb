# frozen_string_literal: true

# canonicalize each local interactive user's home directory (via realpath),
# for shared-home detection. Returns { user => { 'home' => <raw /etc/passwd
# value>, 'exists' => <bool>, 'canonical' => <realpath, or the raw value if
# it doesn't exist or realpath fails> } }.
#
# Shared by read_home_dir_status and read_dot_file_status so both agree on
# what counts as "the same home directory" -- previously each computed this
# independently and drifted out of sync (one used the canonical path for
# shared-detection but a raw-string-keyed dedup guard for glob-once
# optimization, causing duplicate processing for homes shared via
# differently-formatted paths).
def read_canonical_homes(local_interactive_users)
  result = {}
  local_interactive_users.each do |user, home|
    exists = File.directory?(home)
    canonical = if exists
                  begin
                    File.realpath(home)
                  rescue SystemCallError
                    home
                  end
                else
                  home
                end
    result[user] = { 'home' => home, 'exists' => exists, 'canonical' => canonical }
  end
  result
end
