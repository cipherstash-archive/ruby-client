require "logger"

require_relative "./access_key"
require_relative "./client/console"
require_relative "./client/hash_helper"
require_relative "./client/metrics"
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
    # @option rpc_class [Object] a class to use in place of CipherStash::Client::RPC.
    #   This option is used internally for unit testing and is not intended for regular usage.
    #   Defaults to CipherStash::Client::RPC.
    #
    # @option metrics [CipherStash::Client::Metrics] somewhere to collect metrics about this client's operation.
    #   If not provided, no metrics will be collected.
    #   For more information on metrics and how they work, see the documentation for CipherStash::Client::Metrics.
    #
    # @option opts [Hash<Symbol, String | Integer | Boolean>] additional configuration options for the client, which override the values of the corresponding configuration items in the loaded profile, or environment variables.
    #   For the full list of supported option names, see [the Client Configuration reference](https://docs.cipherstash.com/reference/client-configuration.html).
    #
    # @raise [CipherStash::Client::Error::LoadProfileFailure] if the profile could not be loaded for some reason.
    #
    # @raise [CipherStash::Client::Error::InvalidProfileError] if the profile, after being overridden by environment variables and constructor options, was not valid.
    #
    def initialize(profileName: Unspecified, logger: Unspecified, metrics: Metrics::Null.new, rpc_class: RPC,  **opts)
      @logger = if logger == Unspecified
                  Logger.new($stderr).tap { |l| l.level = Logger::WARN; l.formatter = ->(_, _, _, m) { "#{m}\n" } }
                else
                  logger
                end

      if (leftovers = opts.keys - Client.client_options) != []
        raise Error::InvalidProfileError, "Unsupported configuration option(s) found: #{leftovers.inspect}"
      end

      @profile = Profile.load(profileName == Unspecified ? nil : profileName, @logger, **opts)
      @metrics = metrics
      @metrics.created
      @rpc = rpc_class.new(@profile, @logger, @metrics)
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
      @metrics.measure_client_call("collection") do
        @rpc.collection_info(name)
      end
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
      @metrics.measure_client_call("collections") do
        @rpc.collection_list
      end
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
      @metrics.measure_client_call("create_collection") do
        metadata = {
          name: name,
          recordType: schema.fetch("type", {}),
        }

        indexes = schema.fetch("indexes", {}).map do |idx_name, idx_settings|
          {
            meta: index_meta(idx_settings["kind"], idx_name),
            mapping: idx_settings.merge(
              {
                "fieldType" => case idx_settings["kind"]
                when "exact", "range"
                  schema["type"][idx_settings["field"]]
                when "match", "dynamic-match", "field-dynamic-match",
                     "ore-match", "dynamic-ore-match", "field-dynamic-ore-match",
                     "filter-match", "dynamic-filter-match", "field-dynamic-filter-match"
                  "string"
                else
                  raise Error::InvalidSchemaError, "Unknown index kind #{idx_settings["kind"]}"
                end,
                # New match, dynamic-match, and field-dynamic-match indexes should use filter indexes.
                # ORE match indexes require specifically using a *-ore-match index.
                "kind" => case idx_settings["kind"]
                when "match"
                  "filter-match"
                when "dynamic-match"
                  "dynamic-filter-match"
                when "field-dynamic-match"
                  "field-dynamic-filter-match"
                else
                  idx_settings["kind"]
                end
              }
            ),
          }
        end

        begin
          @rpc.create_collection(name, metadata, indexes)
        rescue CipherStash::Client::Error::CollectionCreateFailure => ex
          if ::GRPC::AlreadyExists === ex.cause
            migrate_collection(name, metadata, indexes)
          else
            raise
          end
        end

        true
      end
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
      @metrics.measure_client_call("create_access_key") do
        AccessKey.new(symbolize_keys(console.create_access_key(name, @profile.workspace)))
      end
    end

    # Get the list of currently-extant access keys for the workspace of this client.
    #
    # @return [Array<CipherStash::AccessKey>] details of all the access keys.
    #
    # @raise [CipherStash::Client::Error::ConsoleAccessFailure] if the CipherStash Console, which issues and maintains access keys, could not be contacted.
    #
    def access_keys
      @metrics.measure_client_call("access_keys") do
        console.access_key_list(@profile.workspace).map { |ak| AccessKey.new(symbolize_keys(ak)) }
      end
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
      @metrics.measure_client_call("delete_access_key") do
        console.delete_access_key(name, @profile.workspace)
      end
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
      @metrics.measure_client_call("generate_naming_key") do
        @profile.generate_naming_key
      end
    end

    private

    def console
      @profile.with_access_token do |token|
        Console.new(access_token: token[:access_token], logger: @logger)
      end
    end

    def migrate_collection(name, new_metadata, new_indexes)
      current_collection = collection(name)

      current_collection.indexes.each do |cur_idx|
        new_indexes.each do |new_idx|
          if cur_idx === new_idx
            new_idx[:meta] = cur_idx.meta_settings
          end
        end
      end

      @rpc.migrate_collection(name, new_metadata, new_indexes, current_collection.current_schema_version)
    end

    def index_meta(kind, name)
      case kind
      when "match", "dynamic-match", "field-dynamic-match",
        "filter-match", "dynamic-filter-match", "field-dynamic-filter-match"
        {
          "$indexId" => SecureRandom.uuid,
          "$indexName" => name,
          "$filterKey" =>  SecureRandom.hex(16),
        }
      else
        {
          "$indexId" => SecureRandom.uuid,
          "$indexName" => name,
          "$prfKey" => SecureRandom.hex(16),
          "$prpKey" => SecureRandom.hex(16),
        }
      end
    end
  end
end
