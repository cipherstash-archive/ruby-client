require_relative "../../spec_helper"

require "cipherstash/index/bloom_filter"

describe CipherStash::Index::BloomFilter do
  let(:key) { SecureRandom.hex(16) }

  describe ".new" do
    it "returns a bloom filter with empty bits" do
      filter = described_class.new(key)
      expect(filter.bits).to eq(Set.new())
    end
  end

  describe ".add" do
    it "adds k entries to bits" do
      filter = described_class.new(key)

      filter.add("yes")

      expect(filter.bits.length).to be(filter.k)
    end
  end

  describe ".subset?" do
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
  end
end
