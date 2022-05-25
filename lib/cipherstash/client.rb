require "logger"

require_relative "./access_key"
require_relative "./client/console"
require_relative "./client/hash_helper"
require_relative "./client/profile"
require_relative "./client/rpc"

# Top-level module for all things CipherStash.
module CipherStash
  # An all-in-one client for the CipherStash encrypted searchable data store.
  #
  # This is the only thing you should ever need to explicitly instantiate in order to use CipherStash from Ruby.
  #
  class Client
    include HashHelper

    # A known-unique value that we can use in argument lists to ensure that the value was not given by the user.
    class Unspecified; end
    private_constant :Unspecified

    # Enumerate the list of valid configuration options for a CipherStash client.
    #
    # This is mostly of use to libraries that "wrap" CipherStash::Client (such as `active_stash`), so they can more smoothly handle all configuration parameters without needing to hard-code big long lists.
    #
    # @return [Array<Symbol>] the list of valid profile configuration options.
    #   The option names are in the "canonical" name format, as listed in [the Client Configuration reference](https://docs.cipherstash.com/reference/client-configuration.html), such as `:idpClientSecret`.
    #
    def self.client_options
      Profile.profile_options
    end

    # Create a new CipherStash client.
    #
    # No options are necessary in the common case.
    # The default profile will be loaded from `~/.cipherstash`, modified by any `CS_*` environment variables may be set.
    # Options passed to this constructor directly will further override profile values or environment variables.
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
    #   cs = CipherStash::Client.new(profileName: "ruby-client-profile")
    #
    # @example Load a profile and set a different access key
    #   cs = CipherStash::Client.new(profileName: "example", idpClientSecret: "CSAKSOMETHING.SOMETHING")
    #
    # @option profileName [String] load a specific profile, rather than letting the default client configuration process select a profile for you.
    #   Note that the profile you specify can still have its settings overridden by any relevant environment variables or configuration options passed to the client.
    #
    # @option logger [Logger] specify a custom logger.
    #   If not provided, only warnings and errors will be printed to `stderr`.
    #
    # @option opts [Hash<Symbol, String | Integer | Boolean>] additional configuration options for the client, which override the values of the corresponding configuration items in the loaded profile, or environment variables.
    #   For the full list of supported option names, see [the Client Configuration reference](https://docs.cipherstash.com/reference/client-configuration.html).
    #
    # @raise [CipherStash::Client::Error::LoadProfileFailure] if the profile could not be loaded for some reason.
    #
    # @raise [CipherStash::Client::Error::InvalidProfileError] if the profile, after being overridden by environment variables and constructor options, was not valid.
    #
    def initialize(profileName: Unspecified, logger: Unspecified, **opts)
      @logger = if logger == Unspecified
                  Logger.new($stderr).tap { |l| l.level = Logger::WARN; l.formatter = ->(_, _, _, m) { "#{m}\n" } }
                else
                  logger
                end

      if (leftovers = opts.keys - Client.client_options) != []
        raise Error::InvalidProfileError, "Unsupported configuration option(s) found: #{leftovers.inspect}"
      end

      @profile = Profile.load(profileName == Unspecified ? nil : profileName, @logger, **opts)
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
    rescue ::GRPC::Core::StatusCodes => ex
      @logger.error("CipherStash::Client#collection") { "Unhandled GRPC error!  Please report this as a bug!  #{ex.message} (#{ex.class})" }
      raise
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
    rescue ::GRPC::Core::StatusCodes => ex
      @logger.error("CipherStash::Client#collections") { "Unhandled GRPC error!  Please report this as a bug!  #{ex.message} (#{ex.class})" }
      raise
    end

    # Create a new collection the data store.
    #
    # @param name [String] the name of the collection to create.
    #
    # @param schema [Hash<String, Object>] a description of the structure of the data and indexes in the collection.
    #   Is a Ruby nested hash with a structure identical to that described in [the fine manual](https://docs.cipherstash.com/reference/schema-definition.html).
    #
    # @return [TrueClass]
    #
    # @raise [CipherStash::Client::Error::CollectionCreationFailure] if the collection could not be loaded for some reason, such as if the collection did not exist.
    #
    # @raise [CipherStash::Client::Error::EncryptionFailure] if there was a problem while encrypting the collection or index metadata.
    #
    # @raise [CipherStash::Client::Error::DecryptionFailure] if there was a problem decrypting the naming key.
    #
    def create_collection(name, schema)
      metadata = {
        name: name,
        recordType: schema["type"],
      }

      indexes = schema["indexes"].map do |idx_name, idx_settings|
        {
          meta: {
            "$indexId" => SecureRandom.uuid,
            "$indexName" => idx_name,
            "$prfKey" => SecureRandom.hex(16),
            "$prpKey" => SecureRandom.hex(16),
          },
          mapping: idx_settings.merge(
            {
              fieldType: case idx_settings["kind"]
              when "exact", "range"
                schema["type"][idx_settings["field"]]
              when "match", "dynamic-match", "field-dynamic-match"
                "string"
              else
                raise Error::InvalidSchemaError, "Unknown index kind #{idx_settings["kind"]}"
              end
            }
          ),
        }
      end

      @rpc.create_collection(name, metadata, indexes)

      true
    rescue ::GRPC::Core::StatusCodes => ex
      @logger.error("CipherStash::Client#create_collection") { "Unhandled GRPC error!  Please report this as a bug!  #{ex.message} (#{ex.class})" }
      raise
    end

    # Create a new access key for the workspace of this client.
    #
    # An access key is a secret, long-term credential which allows non-interactive
    # CipherStash clients to access a CipherStash workspace.
    #
    # @param name [String] a unique name to associate with this access key.
    #   Set it to something suitably descriptive, so you know which access key is which.
    #
    # @return [CipherStash::AccessKey] the newly-created access key.
    #
    # @raise [CipherStash::Client::Error::ConsoleAccessFailure] if the CipherStash Console, which issues and maintains access keys, could not be contacted.
    #
    def create_access_key(name)
      AccessKey.new(symbolize_keys(console.create_access_key(name, @profile.workspace)))
    end

    # Get the list of currently-extant access keys for the workspace of this client.
    #
    # @return [Array<CipherStash::AccessKey>] details of all the access keys.
    #
    # @raise [CipherStash::Client::Error::ConsoleAccessFailure] if the CipherStash Console, which issues and maintains access keys, could not be contacted.
    #
    def access_keys
      console.access_key_list(@profile.workspace).map { |ak| AccessKey.new(symbolize_keys(ak)) }
    end

    # Delete an access key from the workspace of this client.
    #
    # Deleting an access key prevents anyone who possesses the access key from being able to get a new (short-lived) access token.
    # An existing access token may still allow access to the data-service for as long as that access token is still valid (up to 15 minutes).
    #
    # @return [Boolean] `true` if the access key was deleted, `false` if the access key did not exist.
    #
    # @raise [CipherStash::Client::Error::ConsoleAccessFailure] if the CipherStash Console, which issues and maintains access keys, could not be contacted.
    #
    def delete_access_key(name)
      console.delete_access_key(name, @profile.workspace)
    end

    # Generate an (encrypted) "naming key" from the wrapping key configured for this client.
    #
    # The naming key is used to deterministically obscure the actual name of the collections in a workspace.
    # It ensures that the client can ask for a collection "by name", while not disclosing that name to the server.
    # A naming key should typically be configured once when a workspace is first created, and then not changed thereafter.
    # This method is only necessary when configuring a workspace that doesn't use CipherStash-generated keys.
    #
    # @return [String]
    def generate_naming_key
      @profile.generate_naming_key
    end

    private

    def console
      @profile.with_access_token do |token|
        Console.new(access_token: token[:access_token], logger: @logger)
      end
    end
  end
end
