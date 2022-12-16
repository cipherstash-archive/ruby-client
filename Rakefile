exec(*(["bundle", "exec", $PROGRAM_NAME] + ARGV)) if ENV['BUNDLE_GEMFILE'].nil?
require 'bundler/gem_tasks'

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

require "./lib/cipherstash/client/ordered_string_test_generator"

desc "Generate test cases for orderise_string to be used by other CipherStash clients"
task :generate_orderise_string_test_cases do
  CipherStash::Client::OrderedStringTestGenerator.new.generate_orderise_string_test_cases
end

desc "Generate test cases for string comparison to be used by other CipherStash clients"
task :generate_string_comparison_test_cases do
  CipherStash::Client::OrderedStringTestGenerator.new.generate_string_comparison_test_cases
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
