begin
  require 'git-version-bump'
rescue LoadError
  nil
end

Gem::Specification.new do |s|
  s.name = "cipherstash-client"

  s.version = GVB.version rescue "0.0.0.1.NOGVB"
  s.date    = GVB.date    rescue Time.now.strftime("%Y-%m-%d")

  s.platform = Gem::Platform::RUBY

  s.summary  = "Official client for the CipherStash encrypted searchable data store"

  s.authors  = ["Matt Palmer", "Dan Draper"]
  s.email    = ["matt@cipherstash.com"]
  s.homepage = "http://github.com/cipherstash/ruby-client"

  s.files = `git ls-files -z`.split("\0").reject { |f| f =~ /^(G|spec|Rakefile)/ }

  s.required_ruby_version = ">= 2.7.0"

  s.add_runtime_dependency "aws-sdk-core", "~> 3.0"
  s.add_runtime_dependency "aws-sdk-kms", "~> 1.0"
  s.add_runtime_dependency 'cbor', '~> 0.5.9.6'
  s.add_runtime_dependency "cipherstash-grpc", "= 0.20220428.11"
  s.add_runtime_dependency "enveloperb", "~> 0.0"
  s.add_runtime_dependency "launchy", "~> 2.5"
  s.add_runtime_dependency "ore-rs", "~> 0.0"

  s.add_development_dependency 'bundler'
  s.add_development_dependency 'fakefs'
  s.add_development_dependency 'github-release'
  s.add_development_dependency 'guard-rspec'
  s.add_development_dependency 'rake', '~> 10.4', '>= 10.4.2'
  s.add_development_dependency 'rb-inotify', '~> 0.9'
  s.add_development_dependency 'redcarpet'
  s.add_development_dependency 'rspec'
  s.add_development_dependency 'simplecov'
  s.add_development_dependency 'yard'
end
