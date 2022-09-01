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

require "rake/extensiontask"

exttask = Rake::ExtensionTask.new("stash_rs", spec) do |ext|
  ext.lib_dir = "lib"
  ext.source_pattern = "*.{rs,toml}"
  ext.cross_compile  = true
  ext.cross_platform = %w[x86_64-linux x86_64-darwin arm64-darwin aarch64-linux]
end

namespace :gem do
  desc "Push all freshly-built gems to RubyGems"
  task :push do
    Rake::Task.tasks.select { |t| t.name =~ %r{^pkg/#{spec.name}-.*\.gem} && t.already_invoked }.each do |pkgtask|
      sh "gem", "push", pkgtask.name
    end

    Rake::Task.tasks
      .select { |t| t.name =~ %r{^gem:cross:} && exttask.cross_platform.include?(t.name.split(":").last) }
      .select(&:already_invoked)
      .each do |task|
      platform = task.name.split(":").last
      sh "gem", "push", "pkg/#{spec.full_name}-#{platform}.gem"
    end
  end

  namespace :cross do
    task :prepare do
      require "rake_compiler_dock"
      sh "bundle package"
    end

    exttask.cross_platform.each do |platform|
      desc "Cross-compile all native gems in parallel"
      multitask :all => platform

      desc "Cross-compile a binary gem for #{platform}"
      task platform => :prepare do
        RakeCompilerDock.sh <<-EOT, platform: platform, image: "rbsys/rcd:#{platform}"
          set -e

          # For cross-building ring; see https://github.com/briansmith/ring/blob/main/BUILDING.md#cross-compiling
          if [ -d "/opt/osxcross/target/bin" ]; then
            # This string replacement is a workaround for https://github.com/oxidize-rb/rb-sys/pull/23
            TARGET_CC="${CARGO_BUILD_TARGET/darwin/darwin20.2}-cc"
            TARGET_AR="${CARGO_BUILD_TARGET/darwin/darwin20.2}-ar"
          else
            TARGET_CC="#{platform}-gnu-gcc"
            TARGET_AR="#{platform}-gnu-ar"
          fi

          export TARGET_CC TARGET_AR

          export GVB_VERSION_OVERRIDE="#{spec.version}"
          [[ "#{platform}" =~ ^a ]] && rustup default nightly
          # This re-installs the nightly version of the relevant target after
          # we so rudely switch the default toolchain
          [ "#{platform}" = "arm64-darwin" ] && rustup target add aarch64-apple-darwin
          [ "#{platform}" = "aarch64-linux" ] && rustup target add aarch64-unknown-linux-gnu

          bundle install
          rake native:#{platform} gem RUBY_CC_VERSION=3.1.0:3.0.0:2.7.0
        EOT
      end
    end
  end
end

task :release do
  sh "git release"
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
RSpec::Core::RakeTask.new :test => :compile do |t|
  t.pattern = "spec/**/*_spec.rb"
end
