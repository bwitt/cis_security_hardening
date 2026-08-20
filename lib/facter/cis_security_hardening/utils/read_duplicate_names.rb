# frozen_string_literal: true

# find names (usernames or group names) that appear more than once in a passwd/group-style file
def read_duplicate_names(file, name_field)
  counts = Hash.new(0)
  File.readlines(file).each do |line|
    fields = line.strip.split(':')
    name = fields[name_field]
    counts[name] += 1 unless name.nil?
  end
  counts.select { |_name, count| count > 1 }.keys
end
