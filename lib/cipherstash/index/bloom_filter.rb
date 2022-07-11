require "openssl"

module CipherStash
  class Index
    class BloomFilter
      attr_reader :bits
      attr_reader :k

      def initialize(key)
        @key = key
        @bits = Set.new()
        @k = 3
      end

      def add(term)
        hash = OpenSSL::HMAC.digest("SHA256", @key, term)

        hash.bytes[0...@k].each do |bit|
          @bits.add(bit)
        end

        self
      end

      def subset?(other)
        @bits.subset?(other.bits)
      end
    end
  end
end
