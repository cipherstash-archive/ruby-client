require "openssl"

module CipherStash
  class Index
    class BloomFilter
      attr_reader :bits
      attr_reader :filter_size
      attr_reader :filter_term_bits

      def initialize(key, opts = {})
        @key = key
        @bits = Set.new()

        # m
        # TODO: raise if m is not a power of two from 256 to 65536
        @filter_size = opts["filterSize"] || 256

        # k
        # TODO: raise if k not in [3, 16]
        @filter_term_bits = opts["filterTermBits"] || 3
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
