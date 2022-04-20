module CipherStash
  # The fundamental unit of storage.
  class Record
    # Create a new record.
    #
    # @private
    #
    def initialize(collection, data)
      @collection, @data = collection, data
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
