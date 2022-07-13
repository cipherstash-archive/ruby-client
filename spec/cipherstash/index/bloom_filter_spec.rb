require_relative "../../spec_helper"

require "cipherstash/index/bloom_filter"

describe CipherStash::Index::BloomFilter do
  # Generated by SecureRandom.hex(32)
  # The same key is used for each test run so that these tests are deterministic.
  let(:key) { "b6d6dba3be33ffaabb83af611ec043b9270dacdc7b3015ce2c36ba17cf2d3b2c" }

  describe ".new" do
    it "returns a bloom filter with empty bits" do
      filter = described_class.new(key)
      expect(filter.bits).to eq(Set.new())
    end

    it "provides a default for filterSize" do
      filter = described_class.new(key)
      expect(filter.filter_size).to eq(256)
    end

    described_class::VALID_FILTER_SIZES.each do |n|
      it "allows #{n} as a value for filterSize" do
        filter = described_class.new(key, {"filterSize" => n})
        expect(filter.filter_size).to eq(n)
      end
    end

    [0, 2, 16, 31, 513, 131072].each do |n|
      it "raises given invalid filterSize #{n}" do
        expect {
          described_class.new(key, {"filterSize" => n})
        }.to raise_error(::CipherStash::Client::Error::InvalidSchemaError, "filterSize must be a power of 2 between 128 and 65536")
      end
    end

    it "provides a default for filterTermBits" do
      filter = described_class.new(key)
      expect(filter.filter_term_bits).to eq(3)
    end

    (3..16).each do |n|
      it "allows #{n} as a value for filterTermBits" do
        filter = described_class.new(key, {"filterTermBits" => n})
        expect(filter.filter_term_bits).to eq(n)
      end
    end

    it "raises when filterTermBits is < 3" do
      expect {
        described_class.new(key, {"filterTermBits" => 2})
      }.to raise_error(::CipherStash::Client::Error::InvalidSchemaError, "filterTermBits must be between 3 and 16")
    end

    it "raises when filterTermBits is > 16" do
      expect {
        described_class.new(key, {"filterTermBits" => 17})
      }.to raise_error(::CipherStash::Client::Error::InvalidSchemaError, "filterTermBits must be between 3 and 16")
    end

    it "raises when the key is too short" do
      key = SecureRandom.hex(16)

      expect {
        described_class.new(key)
      }.to raise_error(::CipherStash::Client::Error::InternalError, "expected bloom filter key to have length=32, got length=16")
    end

    it "raises when the key is empty" do
      key = ""

      expect {
        described_class.new(key)
      }.to raise_error(::CipherStash::Client::Error::InternalError, "expected bloom filter key to have length=32, got length=0")
    end
  end

  describe "#add" do
    # In practice there will be 1 to filter_term_bits entries. Less than filter_term_bits entries will be in the set
    # in the case that any of the first filter_term_bits slices of the HMAC have the same value.
    it "adds filter_term_bits entries to bits" do
      filter = described_class.new(key)

      filter.add("yes")

      expect(filter.bits.length).to eq(filter.filter_term_bits)
    end

    it "returns the bloom filter instance" do
      filter = described_class.new(key)

      result = filter.add("yes")

      expect(result).to be(filter)
    end
  end

  describe "#subset?" do
    it "returns true when the other filter is a subset" do
      filter_a = described_class.new(key)
      filter_b = described_class.new(key)

      filter_a.add("yes")
      filter_b.add("yes")

      expect(filter_a).to be_subset(filter_b)
    end

    it "returns false when the other filter is not a subset" do
      filter_a = described_class.new(key)
      filter_b = described_class.new(key)

      filter_a.add("yes")
      filter_b.add("ner")

      expect(filter_a).not_to be_subset(filter_b)
    end

    described_class::VALID_FILTER_SIZES
      .product((described_class::FILTER_TERM_BITS_MIN..described_class::FILTER_TERM_BITS_MAX).to_a)
      .each do |filter_size, filter_term_bits|
        it "works for filterSize=#{filter_size} and filterTermBits=#{filter_term_bits}" do
          filter_a = described_class.new(key, {"filterSize" => filter_size, "filterTermBits" => filter_term_bits})
          filter_b = described_class.new(key, {"filterSize" => filter_size, "filterTermBits" => filter_term_bits})
          filter_c = described_class.new(key, {"filterSize" => filter_size, "filterTermBits" => filter_term_bits})

          filter_a.add("a")
          filter_a.add("b")

          filter_b.add("a")
          filter_b.add("b")
          filter_b.add("c")

          filter_c.add("d")
          filter_c.add("e")

          expect(filter_a).to be_subset(filter_b)
          expect(filter_c).not_to be_subset(filter_b)
        end
      end
  end
end
