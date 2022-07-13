require_relative "../client/error"

module CipherStash
  class Index
    # A bloom filter implementation designed to be used with the *FilterMatch index classes.
    #
    # @private
    class BloomFilter
      FILTER_TERM_BITS_MIN = 3
      FILTER_TERM_BITS_MAX = 16
      FILTER_TERM_BITS_DEFAULT = 3
      FILTER_SIZE_DEFAULT = 256
      VALID_FILTER_SIZES = [32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536]

      # The "set" bits of the bloom filter
      attr_reader :bits

      # The size of the bloom filter in bits. Commonly referred to as "m". Since we only keep track of the set bits, the filter
      # size determines the maximum value of the positions stored in the bits attr.
      #
      # Valid values are powers of 2 from 32 to 65536.
      #
      # @return [Integer]
      attr_reader :filter_size

      # The number of bits to set per term. Commonly referred to as "k".
      #
      # Valid values are integers from 3 to 16.
      #
      # @return [Integer]
      attr_reader :filter_term_bits

      # Creates a new bloom filter with the given key and filter match index settings.
      #
      # @param key [String] the key to use for hashing terms. Should be provided as a hex-encoded string.
      #
      # @param opts [Hash] the index settings.
      #   "filterSize" and "filterTermBits" are used to set the filter_size and filter_term_bits attrs.
      #
      # @raise [CipherStash::Client::Error::InvalidSchemaError] if an invalid "filterSize" or "filterTermBits" is given.
      def initialize(key, opts = {})
        @key = [key].pack("H*")

        unless @key.length == 32
          raise ::CipherStash::Client::Error::InternalError, "expected bloom filter key to have length=32, got length=#{@key.length}"
        end

        @bits = Set.new()

        @filter_size = opts["filterSize"] || FILTER_SIZE_DEFAULT

        if not VALID_FILTER_SIZES.include?(@filter_size)
          raise ::CipherStash::Client::Error::InvalidSchemaError, "filterSize must be a power of 2 between 128 and 65536"
        end

        @filter_term_bits = opts["filterTermBits"] || FILTER_TERM_BITS_DEFAULT

        if not (FILTER_TERM_BITS_MIN..FILTER_TERM_BITS_MAX).include?(@filter_term_bits)
          raise ::CipherStash::Client::Error::InvalidSchemaError, "filterTermBits must be between 3 and 16"
        end
      end

      # Adds the given term to the bloom filter and returns the filter instance.
      #
      # @param term [String] the term to add
      #
      # @return [CipherStash::Index::BloomFilter]
      def add(term)
        hash = OpenSSL::HMAC.digest("SHA256", @key, term)

        (0..@filter_term_bits-1).map do |slice_idx|
          slice = hash[2*slice_idx..2*slice_idx+1]
          bit_position = slice.unpack("S<").first % @filter_size
          @bits.add(bit_position)
        end

        self
      end

      # Returns true if the bloom filter is a subset of the other bloom filter and returns false otherwise.
      #
      # Can give false positives.
      #
      # @param other [CipherStash::Index::BloomFilter] the other bloom filter to check against.
      #
      # @return [Boolean]
      def subset?(other)
        @bits.subset?(other.bits)
      end
    end
  end
end
