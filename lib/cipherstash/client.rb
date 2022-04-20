require "logger"

require_relative "./client/rpc"
require_relative "./client/profile"
require_relative "./analysis/text_processor"

# Top-level module for all things CipherStash.
module CipherStash
  # An all-in-one client for the CipherStash encrypted searchable data store.
  #
  # This is the only thing you should ever need to explicitly instantiate in order to use CipherStash from Ruby.
  #
  class Client
    # A known-unique value that we can use in argument lists to ensure that the value was not given by the user.
    class Unspecified; end
    private_constant :Unspecified

    # Create a new CipherStash client.
    #
    # No options are necessary in the common case.
    # The default profile will be loaded from `~/.cipherstash`, modified by any `CS_*` environment variables may be set.
    #
    # @see https://docs.cipherstash.com/reference/client-configuration.html Client Configuration reference documentation
    #
    # @example Load profile from disk and/or environment
    #   cs = CipherStash::Client.new
    #
    # @example Specify a custom logger
    #   logger = Logger.new
    #   logger.level = Logger::DEBUG
    #
    #   cs = CipherStash::Client.new(logger: logger)
    #
    # @example Load specified profile by name
    #   # This loads the given profile, but options will
    #   # still be overridden by env vars, if present
    #   cs = CipherStash::Client.new(profileName: "ruby-client-profile"
    #
    # @option profileName [String] load a specific profile, rather than letting the default client configuration process select a profile for you.
    #   Note that the profile you specify can still have its settings overridden by any relevant environment variables.
    #
    # @option logger [Logger] specify a custom logger.
    #   If not provided, only warnings and errors will be printed to `stderr`.
    #
    # @raise [CipherStash::Client::Error::LoadProfileFailure] if the profile could not be loaded, or was considered invalid for some reason.
    #
    def initialize(profileName: Unspecified, logger: Unspecified)
      @logger = if logger == Unspecified
                  Logger.new($stderr).tap { |l| l.level = Logger::WARN; l.formatter = ->(_, _, _, m) { "#{m}\n" } }
                else
                  logger
                end

      @profile = Profile.load(profileName == Unspecified ? nil : profileName, @logger)
      @rpc = RPC.new(@profile, @logger)
    end

    # Load an existing collection from the data store by name.
    #
    # @param name [String] the name of the collection to load.
    #
    # @raise [CipherStash::Client::Error::CollectionInfoFailure] if the collection could not be loaded for some reason, such as if the collection did not exist.
    #
    # @raise [CipherStash::Client::Error::DecryptionFailure] if there was a problem while decrypting the collection or index metadata.
    #
    # @return [CipherStash::Collection]
    #
    def collection(name)
      @rpc.collection_info(name)
    end

    # Load all collections in the data store.
    #
    # @raise [CipherStash::Client::Error::CollectionListFailure] if there was a problem while listing the collections.  Almost certainly a server-side failure.
    #
    # @raise [CipherStash::Client::Error::DecryptionFailure] if there was a problem while decrypting a piece of collection or index metadata.
    #
    # @return [Array<CipherStash::Collection>]
    #
    def collections
      @rpc.collection_list
    end
  end
end
