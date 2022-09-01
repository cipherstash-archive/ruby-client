module StashRs
end

begin
  RUBY_VERSION =~ /(\d+\.\d+)/
  require_relative "./#{$1}/stash_rs"
rescue LoadError
  begin
    require_relative "./stash_rs.#{RbConfig::CONFIG["DLEXT"]}"
  rescue LoadError
    raise LoadError, "Failed to load stash_rs.#{RbConfig::CONFIG["DLEXT"]}; either it hasn't been built, or was built incorrectly for your system"
  end
end

require_relative "./stash_rs/record"
require_relative "./stash_rs/record_indexer"
