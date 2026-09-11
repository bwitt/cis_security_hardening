# frozen_string_literal: true

require 'spec_helper'
require 'facter/cis_security_hardening/utils/read_duplicate_names'

describe 'read_duplicate_names' do
  before do
    allow(File).to receive(:readlines).with('/etc/passwd').and_return(
      [
        "root:x:0:0:root:/root:/bin/bash\n",
        "dupuser:x:1000:1000::/home/dupuser:/bin/bash\n",
        "dupuser:x:1001:1001::/home/dupuser2:/bin/bash\n",
        "uniqueuser:x:1002:1002::/home/uniqueuser:/bin/bash\n",
      ]
    )
  end

  it 'returns names that appear more than once' do
    expect(read_duplicate_names('/etc/passwd', 0)).to eq(['dupuser'])
  end

  it 'excludes names that appear only once' do
    expect(read_duplicate_names('/etc/passwd', 0)).not_to include('root', 'uniqueuser')
  end
end
