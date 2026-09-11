# frozen_string_literal: true

# find IDs (UID or GID) that are shared by more than one name in a passwd/group-style file
# returns a hash of { id => [names] } for every id used by 2+ names
def read_duplicate_ids(file, id_field, name_field)
  names_by_id = Hash.new { |h, k| h[k] = [] }
  File.readlines(file).each do |line|
    fields = line.strip.split(':')
    id = fields[id_field]
    name = fields[name_field]
    next if id.nil? || name.nil?

    names_by_id[id].push(name)
  end
  names_by_id.select { |_id, names| names.length > 1 }
end
