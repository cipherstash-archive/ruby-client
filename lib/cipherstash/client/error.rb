module CipherStash
  class Client
    # The base class for all exceptions raised by `CipherStash::Client`.
    class Error < StandardError
      # An error occurred while attempting to load a profile.
      #
      # The exception message will describe the exact problem.
      class LoadProfileFailure < Error; end

      # An error occured whilst trying to decrypt a ciphertext.
      #
      # The exception message will describe the exact problem.
      class DecryptionFailure < Error; end

      # An error occured while performing a remote procedure call to the data-service.
      class RPCFailure < Error; end

      # An error occured while getting a collection's info.
      class CollectionInfoFailure < RPCFailure; end

      # An error occured while listing the collections in the workspace.
      class CollectionListFailure < RPCFailure; end

      # An error occured while deleting a collection.
      class CollectionDeleteFailure < RPCFailure; end

      # An error occured while retrieving one or more records by ID.
      class RecordGetFailure < RPCFailure; end

      # An error occured while storing a record.
      class RecordPutFailure < RPCFailure; end

      # An error occured while deleting a record.
      class RecordDeleteFailure < RPCFailure; end

      # An error occured while executing a query.
      class DocumentQueryFailure < RPCFailure; end

      # A query constraint was specified incorrectly.
      #
      # Either a non-existent index was referenced, or an operator was specified that is not supported on the given index.
      class QueryConstraintError < Error; end

      # An attempt was made to retrieve data from a record stored in index-only mode.
      class IndexOnlyRecordError < Error; end
    end
  end
end
