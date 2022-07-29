exec(*(["bundle", "exec", $PROGRAM_NAME] + ARGV)) if ENV['BUNDLE_GEMFILE'].nil?

task :default => :test

begin
  Bundler.setup(:default, :development)
rescue Bundler::BundlerError => e
  $stderr.puts e.message
  $stderr.puts "Run `bundle install` to install missing gems"
  exit e.status_code
end

spec = Bundler.load_gemspec("cipherstash-client.gemspec")
require "rubygems/package_task"

Gem::PackageTask.new(spec) { |pkg| }

namespace :gem do
  desc "Push all freshly-built gems to RubyGems"
  task :push do
    Rake::Task.tasks.select { |t| t.name =~ %r{^pkg/#{spec.name}-.*\.gem} && t.already_invoked }.each do |pkgtask|
      sh "gem", "push", pkgtask.name
    end
  end
end

task :release do
  sh "git release"
end

require "securerandom"
require "./lib/cipherstash/index"
require "json"

task :generate_ordered_string_test_cases do
  id = SecureRandom.uuid
  settings = {
    "meta" => {
      "$indexId" => id,
      "$indexName" => "titleSort",
      "$prfKey" => SecureRandom.hex(16),
      "$prpKey" => SecureRandom.hex(16),
    },
    "mapping" => {
      "kind" => "range",
      "field" => "title",
      "fieldType"=>"string",
    }
  }
  schema_versions = {:first=>0, :last=>0, :searchable=>true}

  index = CipherStash::Index.generate(id, settings, schema_versions)

  random_ascii_string = -> () do
    unicode_char_max = 127
    max_string_length = 200
    (0..rand(max_string_length -1)).map { rand(unicode_char_max + 1).chr }.join
  end

  num_test_cases = 1_000

  orderise_string_cases = (0..(num_test_cases - 1)).map do
    str = random_ascii_string.call
    output = index.__send__ :orderise_string, str
    {input: str, output: output}
  end

  File.write("orderise_string_test_cases.json", orderise_string_cases.to_json)

  num_test_cases = 100

  string_comparison_cases = (0..(num_test_cases - 1)).map do
    str_a = random_ascii_string.call
    terms_a = index.__send__ :orderise_string, str_a

    str_b = random_ascii_string.call
    terms_b = index.__send__ :orderise_string, str_b

    output = case terms_a <=> terms_b
      when -1
        "<"
      when 0
        "=="
      when 1
        ">"
      end

    {input: [str_a, str_b], output: output}
  end

  File.write("string_comparison_test_cases.json", string_comparison_cases.to_json)
end

require 'yard'

YARD::Rake::YardocTask.new :doc do |yardoc|
  yardoc.files = %w{lib/**/*.rb - README.md}
end

desc "Run guard"
task :guard do
  sh "guard --clear"
end

require 'rspec/core/rake_task'
RSpec::Core::RakeTask.new :test do |t|
  t.pattern = "spec/**/*_spec.rb"
end
