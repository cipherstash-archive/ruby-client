require "openssl"
require_relative "../client/error"

module CipherStash
  class Index
    class BloomFilter
      FILTER_TERM_BITS_MIN = 3
      FILTER_TERM_BITS_MAX = 16
      FILTER_TERM_BITS_DEFAULT = 3
      FILTER_SIZE_DEFAULT = 256
      VALID_FILTER_SIZES = [32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536]

      private_constant :FILTER_TERM_BITS_MIN, :FILTER_TERM_BITS_MAX, :FILTER_TERM_BITS_DEFAULT,
        :FILTER_SIZE_DEFAULT, :VALID_FILTER_SIZES

      attr_reader :bits
      attr_reader :filter_size
      attr_reader :filter_term_bits

      def initialize(key, opts = {})
        @key = key
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

      def add(term)
        hash = OpenSSL::HMAC.digest("SHA256", @key, term)

        (0..@filter_term_bits-1).map do |slice_idx|
          slice = hash[2*slice_idx..2*slice_idx+1]
          bit_position = slice.unpack("S<").first % @filter_size
          @bits.add(bit_position)
        end

        self
      end

      def subset?(other)
        @bits.subset?(other.bits)
      end
    end
  end
end
