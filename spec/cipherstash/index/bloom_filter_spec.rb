require_relative "../../spec_helper"

require "cipherstash/index/bloom_filter"

describe CipherStash::Index::BloomFilter do
  # Generated by SecureRandom.hex(16)
  # The same key is used for each test run so that these tests are deterministic.
  let(:key) { "8b42157da439e06aa6f6d1ad8c1db72e" }

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

    [0, 2, 64, 127, 513, 131072].each do |n|
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

          filter_a.add("c")
          filter_a.add("d")

          filter_b.add("a")
          filter_b.add("b")
          filter_b.add("c")
          filter_b.add("d")
          filter_b.add("e")

          filter_c.add("f")

          expect(filter_a).to be_subset(filter_b)
          expect(filter_c).not_to be_subset(filter_b)
        end
      end
  end
end
