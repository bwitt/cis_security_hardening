# frozen_string_literal: true

require 'spec_helper'
require 'json'
require 'puppet/pops'

# The Bolt tasks in this module are plain shell scripts paired with a JSON
# metadata file. Nothing else in the toolchain checks that the two agree with
# each other, so do it here.
describe 'task metadata' do
  tasks_dir = File.expand_path('../../tasks', __dir__)
  metadata_files = Dir[File.join(tasks_dir, '*.json')].sort

  it 'has tasks to check' do
    expect(metadata_files).not_to be_empty
  end

  it 'has metadata for every task implementation' do
    implementations = Dir[File.join(tasks_dir, '*.sh')].map { |f| File.basename(f, '.sh') }
    documented = metadata_files.map { |f| File.basename(f, '.json') }
    expect(implementations - documented).to be_empty
  end

  metadata_files.each do |metadata_file|
    task_name = File.basename(metadata_file, '.json')
    implementation = metadata_file.sub(%r{\.json\z}, '.sh')
    metadata = JSON.parse(File.read(metadata_file))
    parameters = metadata['parameters'] || {}

    describe task_name do
      it 'has a description' do
        expect(metadata['description']).to be_a(String).and(satisfy { |d| !d.empty? })
      end

      it 'reads its parameters from the environment' do
        expect(metadata['input_method']).to eq('environment')
      end

      it 'has an implementation' do
        expect(File).to exist(implementation)
      end

      it 'has an implementation starting with a shebang' do
        expect(File.readlines(implementation).first).to start_with('#!')
      end

      parameters.each do |param_name, param|
        context "parameter #{param_name}" do
          it 'has a description' do
            expect(param['description']).to be_a(String).and(satisfy { |d| !d.empty? })
          end

          it 'declares a valid Puppet data type' do
            expect { Puppet::Pops::Types::TypeParser.singleton.parse(param['type']) }.not_to raise_error
          end

          it 'has a default matching its declared data type' do
            skip 'no default declared' unless param.key?('default')

            type = Puppet::Pops::Types::TypeParser.singleton.parse(param['type'])
            expect(type.instance?(param['default'])).to be(true),
                                                        "default #{param['default'].inspect} is not a #{param['type']}"
          end

          it 'is used by the implementation' do
            expect(File.read(implementation)).to include("PT_#{param_name}")
          end
        end
      end

      it 'declares every task parameter its implementation uses' do
        used = File.read(implementation).scan(%r{PT_([A-Za-z_][A-Za-z0-9_]*)}).flatten.uniq
        expect(used - parameters.keys).to be_empty
      end
    end
  end
end
