require "bson"
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
    def initialize(rpc, id, ref, metadata, indexes)
      @rpc, @id, @ref, @metadata, @indexes = rpc, id, ref, metadata, indexes
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
      id = SecureRandom.uuid

      vectors = @indexes.map { |idx| idx.analyze(id, record) }.compact
      @rpc.put(self, id, store_record ? record : nil, vectors)

      id
    end

    # Update-or-insert a record in the collection.
    #
    # If a record with the given ID already exists in the collection, its contents (and indexes) will be updated.
    # Otherwise, a new record will be inserted, with the ID specified.
    #
    # @param record [String] the human-readable UUID of the record.
    #
    # @param record [Hash] the complete record to store in the database.
    #
    # @option store_record [Boolean] if set to false, the record data itself will not be stored in the data store.
    #
    # @return [void]
    #
    # @raise [CipherStash::Client::Error::RecordPutFailure] if the record could not be inserted for some reason.
    #
    # @raise [CipherStash::Client::Error::EncryptionFailure] if there was a problem encrypting the record.
    #
    # @raise [CipherStash::Client::Error::RPCFailure] if a low-level communication problem with the server caused the insert to fail.
    #
    def upsert(id, record, store_record: true)
      unless id.is_a?(String)
        raise ArgumentError, "Must provide a string ID"
      end

      vectors = @indexes.map { |idx| idx.analyze(id, record) }.compact
      @rpc.put(self, id, store_record ? record : nil, vectors)

      nil
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
      if id.is_a?(Array)
        @rpc.get_all(self, id)
      else
        @rpc.get(self, id)
      end
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
      @rpc.delete(self, id)
    end

    # Remove the collection from the data-service.
    #
    # As you can imagine, this is a fairly drastic operation.
    # Don't call it on a whim.
    #
    def drop
      @rpc.delete_collection(self)
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
    #
    # # Aggregating Results
    #
    # TBA
    #
    #
    # # Sorting
    #
    # TBA
    #
    #
    # # Limiting the Number of Results
    #
    # TBA
    #
    #
    # @return [CipherStash::Client::Error::InvalidIndex] if the index name you specified for a constraint is not defined on the collection.
    #
    # @return [CipherStash::Client::Error::InvalidOperator] if the operator you specified for a constraint is not valid for the type of index being used.
    #
    def query(&blk)
      q = Query.new(self)
      @rpc.query(self, q.parse(&blk))
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
  end
end
