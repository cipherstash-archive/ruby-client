module CipherStash
  # The fundamental unit of storage.
  class Record
    # The ID of the record.
    #
    # @return [String] a human-readable formatted UUID.
    attr_reader :id

    # Create a new record.
    #
    # @private
    #
    def initialize(id, data)
      @id, @data = id, data
    end

    # Fetch the value of a top-level key in a record.
    #
    # @param k [String] the key to lookup.
    #
    # @return [Object, NilClass]
    #
    def [](k)
      @data[k]
    end
  end
end
