require "logger"
require "securerandom"

require_relative "./collection/query"

module CipherStash
  # A group of similar records stored in the CipherStash searchable encrypted data store.
  #
  # This class is not ordinarily instantiated directly.
  # Instead, instances of this class are created by calling CipherStash::Client#collection or CipherStash::Client#collections.
  #
  class Collection
    # @return [String] collection UUID, in human-readable form
    #
    # @private
    attr_reader :id

    # The hashed "ref" of the collection
    #
    # @return [String] the ref as a raw binary
    #
    # @private
    attr_reader :ref

    # Create a new collection from its retrieved metadata.
    #
    # @private
    def initialize(rpc, id, ref, metadata, indexes, schema_versions:, logger: nil, metrics:)
      @rpc, @id, @ref, @metadata, @indexes, @schema_versions, @metrics = rpc, id, ref, metadata, indexes, schema_versions, metrics
      @logger = logger || Logger.new("/dev/null")
    end

    # The plaintext name of the collection.
    #
    # @return [String]
    #
    def name
      @metadata["name"]
    end

    # Store a new record in the collection.
    #
    # @param record [Hash] the complete record to store in the database.
    #
    # @option store_record [Boolean] if set to false, the record data itself will not be stored in the data store.
    #   DEPRECATED.
    #
    # @return [String] the UUID of the newly-created record.
    #
    # @raise [CipherStash::Client::Error::RecordPutFailure] if the record could not be inserted for some reason.
    #
    # @raise [CipherStash::Client::Error::EncryptionFailure] if there was a problem encrypting the record.
    #
    # @raise [CipherStash::Client::Error::RPCFailure] if a low-level communication problem with the server caused the insert to fail.
    #
    def insert(record, store_record: true)
      @metrics.measure_client_call("insert") do
        unless store_record
          @logger.debug("CipherStash::Collection#insert") { "DEPRECATION NOTICE: 'store_record: false' is no longer supported; please stop using it" }
        end

        uuid = SecureRandom.uuid

        vectors = @indexes.map { |idx| idx.analyze(uuid, record) }.compact
        @rpc.put(self, uuid, record, vectors)

        uuid
      end
    rescue ::GRPC::Core::StatusCodes => ex
      @logger.error("CipherStash::Collection#insert") { "Unhandled GRPC error!  Please report this as a bug!  #{ex.message} (#{ex.class})" }
      raise
    end

    # Update-or-insert a record in the collection.
    #
    # If a record with the given ID already exists in the collection, its contents (and indexes) will be updated.
    # Otherwise, a new record will be inserted, with the ID specified.
    #
    # @param id [String] the human-readable UUID of the record.
    #
    # @param record [Hash] the complete record to store in the database.
    #
    # @option store_record [Boolean] if set to false, the record data itself will not be stored in the data store.
    #   DEPRECATED.
    #
    # @return [TrueClass]
    #
    # @raise [CipherStash::Client::Error::RecordPutFailure] if the record could not be inserted for some reason.
    #
    # @raise [CipherStash::Client::Error::EncryptionFailure] if there was a problem encrypting the record.
    #
    # @raise [CipherStash::Client::Error::RPCFailure] if a low-level communication problem with the server caused the insert to fail.
    #
    def upsert(id, record, store_record: true)
      @metrics.measure_client_call("upsert") do
        unless store_record
          @logger.debug("CipherStash::Collection#upsert") { "DEPRECATION NOTICE: 'store_record: false' is no longer supported; please stop using it" }
        end

        unless id.is_a?(String)
          raise ArgumentError, "Must provide a string ID"
        end

        vectors = @indexes.map { |idx| idx.analyze(id, record) }.compact
        @rpc.put(self, id, store_record ? record : nil, vectors)

        true
      end
    rescue ::GRPC::Core::StatusCodes => ex
      @logger.error("CipherStash::Collection#upsert") { "Unhandled GRPC error!  Please report this as a bug!  #{ex.message} (#{ex.class})" }
      raise
    end

    # Bulk insert-or-update of many records into the collection.
    #
    # When you have a lot of records that need to be upserted into the collection, doing them one-by-one with #upsert can take a long time, because each upsert needs to complete before you can start the next one.
    # By using this "streaming" upsert instead, you can just mass-spam records into the collection, which greatly reduces round-trips (and hence round-trip wait time).
    #
    # To stream records, you provide any object that responds to `#each` (in the manner of an enumerable) and yields a series of `{ id: <uuid>, record: <hash> }` objects.
    # For small record sets this enumerable can be an array, but for larger data sets you could stream the inputs from, say, a Postgres database using cursors.
    #
    # @example Stream an array of records
    #   records = [
    #     {
    #       id: "9a08f6c9-faf3-4bcf-a5eb-fcaf066a9b3f",
    #       record: {
    #         title: "Star Trek: The Motion Picture",
    #         runningTime: 132,
    #         year: 1979,
    #       },
    #     },
    #     {
    #       id: "f7f6443b-99c0-4579-9721-d77052769f44",
    #       record: {
    #         title: "Star Trek II: The Wrath of Khan",
    #         runningTime: 113,
    #         year: 1982,
    #       },
    #     },
    #     # etc etc etc
    #   }
    #   count = collection.streaming_upsert(records)
    #   puts "Upserted #{count} records"
    #
    # @example Stream lots (possibly billions) of records from an ActiveRecord model, using streaming
    #   count = collection.streaming_upsert(User.find_each)
    #   puts "Upserted #{count} records"
    #
    # @return [Integer] the number of records upserted into the database, including exact duplicates.
    #
    # @raise [CipherStash::Client::Error::StreamingPutFailure] if the record could not be inserted for some reason.
    #
    # @raise [CipherStash::Client::Error::EncryptionFailure] if there was a problem encrypting the record.
    #
    # @raise [CipherStash::Client::Error::RPCFailure] if a low-level communication problem with the server caused the insert to fail.
    #
    def streaming_upsert(records)
      @metrics.measure_client_call("streaming_upsert") do
        records = records.lazy.map do |r|
          @metrics.measure_rpc_call("putStream", :excluded) do
            unless r.is_a?(Hash) && r.key?(:id) && r.key?(:record)
              raise ArgumentError, "Malformed record passed to streaming_upsert: #{r.inspect}"
            end
            vectors = @indexes.map { |idx| idx.analyze(r[:id], r[:record]) }.compact
            [r[:id], r[:record], vectors]
          end
        end

        @rpc.put_stream(self, records)
      end
    rescue ::GRPC::Core::StatusCodes => ex
      @logger.error("CipherStash::Collection#streaming_upsert") { "Unhandled GRPC error!  Please report this as a bug!  #{ex.message} (#{ex.class})" }
      raise
    end

    # Retrieve one or more records from the collection.
    #
    # @param id [String, Array<String>] the ID(s) of the record(s) to retrieve.
    #   Each should be a human-readable UUID of a record in the collection.
    #
    # @return [CipherStash::Record, Array<CipherStash::Record>] the record(s) corresponding to the ID(s) provided.
    #   If a single ID was given, then a single record will be returned, while if an array of records was given (even an array with a single element), then an array of records will be returned.
    #
    # @raise [CipherStash::Client::Error::RecordGetFailure] if the record(s) could not be retrieved for some reason.
    #
    # @raise [CipherStash::Client::Error::DecryptionFailure] if there was a problem decrypting the data returned.
    #
    # @raise [CipherStash::Client::Error::RPCFailure] if a low-level communication problem with the server caused the operation to fail.
    #
    def get(id)
      @metrics.measure_client_call("get") do
        if id.is_a?(Array)
          @rpc.get_all(self, id)
        else
          @rpc.get(self, id)
        end
      end
    rescue ::GRPC::Core::StatusCodes => ex
      @logger.error("CipherStash::Collection#get") { "Unhandled GRPC error!  Please report this as a bug!  #{ex.message} (#{ex.class})" }
      raise
    end

    # Delete a record from the collection.
    #
    # @param id [String] the ID of the record, as a human-readable UUID.
    #
    # @return [void]
    #
    # @raise [CipherStash::Client::Error::RecordDeleteFailure] if the record could not be deleted for some reason.
    #
    # @raise [CipherStash::Client::Error::RPCFailure] if a low-level communication problem with the server caused the operation to fail.
    #
    def delete(id)
      @metrics.measure_client_call("delete") do
        @rpc.delete(self, id)
      end
    rescue ::GRPC::Core::StatusCodes => ex
      @logger.error("CipherStash::Collection#delete") { "Unhandled GRPC error!  Please report this as a bug!  #{ex.message} (#{ex.class})" }
      raise
    end

    # Remove the collection from the data-service.
    #
    # As you can imagine, this is a fairly drastic operation.
    # Don't call it on a whim.
    #
    def drop
      @metrics.measure_client_call("drop") do
        @rpc.delete_collection(self)
      end
    rescue ::GRPC::Core::StatusCodes => ex
      @logger.error("CipherStash::Collection#drop") { "Unhandled GRPC error!  Please report this as a bug!  #{ex.message} (#{ex.class})" }
      raise
    end

    # Search for records in the collection which match the constraints specified.
    #
    # The constraints, aggregations, and other ephemera are all defined in a block which is passed to the query.
    # This block receives an object which has methods for each of the indexes defined on the collection, which in turn can be used to specify constraints.
    # The object passed to the block also has special methods for defining aggregations, sorting, and limits.
    #
    # # Defining constraints
    #
    # A constraint consists of an *index*, an *operator*, and a *value*.
    # We'll define all this in detail, but you can *probably* just get away with looking at the examples, below, to get the gist of the thing.
    #
    # The *index* is any index defined on the collection.
    # To specify the index to use for a constraint is specified, call a method with the same name as the index on the object passed to the `query` block.
    #
    # The *operator* is specified by calling a method named for the operator on the object returned from the call to the index name.
    # Which operator(s) can be used depends on the type of the index you're using for the constraint.
    # For example, the `eq` (equality) operator can be used on "exact" and "range" indexes, while the `lt` (less-than) operator is only valid on "range" indexes.
    #
    # If you try to specify an index that doesn't exist, or an operator that is not valid for the index type given, or you try to use an invalid operator for the index type, an exception will be raised.
    #
    # The *value* is passed as an argument to the operator method call.
    # All operators currently take a single argument.
    # Ensure that the type of the value you pass is of the same type as the data in the index.
    # In particular, bear in mind that `42` (an integer) is not the same, from an indexing perspective, as `42.0` (a float), even though the two compare equally in Ruby.
    # There are currently no runtime checks to ensure type correctness.
    #
    # To require multiple constraints to match in order for a record to be returned (an `AND` query), specify each constraint in the query block.
    # They will be automatically combined.
    # There is not (currently) any way to perform an `OR` operation in a query; you must perform multiple queries and combine the results yourself.
    #
    # @example Search for movies with an exact title
    #   collection.query do |movies|
    #     movies.exactTitle.eq("Star Trek: The Motion Picture")
    #   end
    #
    # @example Search for movies made after 2015
    #   collection.query do |movies|
    #     movies.year.gt(2015.0)
    #   end
    #
    # @example Search for movies less than an hour long
    #   collection.query do |movies|
    #     movies.runningTime.lt(60.0)
    #   end
    #
    # @example Search for movies less than an hour long *and* made after 2015
    #   collection.query do |movies|
    #     movies.runningTime.lt(60.0)
    #     movies.year.gt(2015.0)
    #   end
    #
    # ## Dynamic Constraints
    #
    # While the literate DSL described above is useful for "literal" queries, if you're generating queries programmatically it is somewhat cumbersome to use (a lot of calls to `#__send__`).
    # So, you can instead use the `#add_constraint` method in the block to define your constraints.
    # It uses the same inputs -- an index name, an operator, and arguments -- but in a single method call.
    #
    # @example Using `#add_constraint` to find movies less than an hour long and made after 2015
    #   collection.query do |movies|
    #     movies.add_constraint("runningTime", "lt", 60.0)
    #     movies.add_constraint("year", "gt", 2015.0)
    #   end
    #
    # # Aggregating Results
    #
    # TBA
    #
    #
    # # Sorting
    #
    # To specify a sorting strategy, use the `order_by` method on the object passed to the query block.
    # It takes one required argument, the name of an index, and an optional second argument, which can be either `:ASC` or `:DESC`, which specifies the direction of sorting.
    # The index you specify must be of a type that supports ordering (only the "range" index type does at present).
    #
    # You can call `order_by` more than once; ordering strategies are applied in the order they are specified.
    #
    #
    # # Limiting the Number of Results
    #
    # Limits and offsets can be handled by passing `:limit` and `:offset` to the query method.
    #
    # @example Limit to the first 5 results
    #   collection.query(limit: 5) do |movies|
    #     movies.year.gt(1990.0)
    #   end
    #
    # @example Return 5 results offset by 20
    #   collection.query(limit: 5, offset: 20) do |movies|
    #     movies.year.gt(1990.0)
    #   end
    #
    # @return [CipherStash::Collection::QueryResult]
    #
    # @raise [CipherStash::Client::Error::QueryConstraintError] if the index name you specified for a constraint is not defined on the collection, or the operator you specified is not supported by the associated index type.
    #
    # @raise [CipherStash::Client::Error::QueryOrderingError] if some aspect of an `order_by` call was invalid.
    #
    # @raise [CipherStash::Client::Error::DocumentQueryFailure] if the query could not be executed.
    #
    # @raise [CipherStash::Client::Error::EncryptionFailure] if there was a problem encrypting the record.
    #
    # @raise [CipherStash::Client::Error::RPCFailure] if a low-level communication problem with the server caused the query to fail.
    #
    def query(opts = {}, &blk)
      @metrics.measure_client_call("query") do
        q = Query.new(self, opts)
        @rpc.query(self, *q.parse(&blk))
      end
    rescue ::GRPC::Core::StatusCodes => ex
      @logger.error("CipherStash::Collection#query") { "Unhandled GRPC error!  Please report this as a bug!  #{ex.message} (#{ex.class})" }
      raise
    end

    # Re-index out-of-date records to the collection's current indexes
    #
    # @return [TrueClass]
    #
    def migrate_records
      @metrics.measure_client_call("migrate_records") do
        @rpc.migrate_records(self) do |uuid, data|
          indexes.map { |idx| idx.analyze(uuid, data) }.compact
        end

        true
      end
    end

    # Reload the collection's metadata and indexes from the data-service
    #
    # After a schema migration or re-indexing -- either by this client or another client running at the same time -- the indexes and metadata cached in this Collection object can be out-of-date with regards to the server.
    # Calling this method requests the current information about the collection from the server, and updates this object's information to match.
    #
    # @return [TrueClass]
    #
    def reload
      @metrics.measure_client_call("reload") do
        new_collection = @rpc.collection_info(name)

        @metadata = new_collection.metadata
        @indexes = new_collection.indexes
        @schema_versions = new_collection.schema_versions

        true
      end
    end

    # Retrieve the index with the specified name
    #
    # @private
    #
    # @param name [String] the name of the index
    #
    # @return [CipherStash::Index, NilClass] the index object if an index with
    #   the specified name exists, or `nil` otherwise
    #
    def index_named(name)
      @indexes.find { |idx| idx.name == name }
    end

    # Get all the indexes defined on the collection
    #
    # @private
    #
    # @return [Array<CipherStash::Index>]
    #
    attr_reader :indexes

    # Get the collection metadata.
    #
    # @private
    #
    attr_reader :metadata

    # Get all the schema version info
    #
    # @private
    #
    attr_reader :schema_versions

    # The current schema version of the collection
    #
    # @private
    #
    # @return [Integer]
    #
    def current_schema_version
      @schema_versions[:current]
    end

    # The first (earliest) active schema version of the collection
    #
    # @private
    #
    # @return [Integer]
    #
    def first_active_schema_version
      @schema_versions[:first_active]
    end
    # The last (most recent) active schema version of the collection
    #
    # @private
    #
    # @return [Integer]
    #
    def last_active_schema_version
      @schema_versions[:last_active]
    end
  end
end
