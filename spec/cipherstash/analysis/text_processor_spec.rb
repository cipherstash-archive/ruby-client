require 'cipherstash/analysis/text_processor'
require "cipherstash/client"

RSpec.describe CipherStash::Analysis::TextProcessor do
  describe "Standard text processor" do
    it "splits text based on word boundaries" do
      tokenizer =
        CipherStash::Analysis::TextProcessor.new({
          "tokenFilters" => [
            { "kind" => "downcase" }
          ],
         "tokenizer" => { "kind" => "standard" }
        })
      result = tokenizer.perform("This is an example of a standard tokenizer")
      expect(result.length).to eq(8)
      expect(result).to eq(["this", "is", "an", "example", "of", "a", "standard", "tokenizer"])
    end
  end

  describe "Standard text processor with an ngram filter" do
    it "raises an error if min length and max length are not provided" do
      expect {
        CipherStash::Analysis::TextProcessor.new({
          "tokenFilters" => [
            { "kind" => "downcase" },
            { "kind" => "ngram" }
          ],
          "tokenizer" => { "kind" => "standard" }
        })
      }.to raise_error(CipherStash::Client::Error::InternalError, "Min length and max length not provided with ngram filter. Please specify ngram token length using '{kind: :ngram, min_length: 3, max_length: 8}'")
    end

    ["1", { foo: "bar" }, Object.new].each do |length|
      it "raises an error if invalid length of #{length.inspect} provided" do
        expect {
          CipherStash::Analysis::TextProcessor.new({
            "tokenFilters" => [
              { "kind" => "downcase" },
              { "kind" => "ngram", "minLength" => length, "maxLength" => length }
              ],
            "tokenizer" => { "kind" => "standard" }
          })
        }.to raise_error(CipherStash::Client::Error::InternalError, "The values provided to the min and max length must be of type Integer.")
      end
    end

    it "raises an error if the min length is greater than the max length" do
      expect {
        CipherStash::Analysis::TextProcessor.new({
          "tokenFilters" => [
            { "kind" => "downcase" },
            { "kind" => "ngram", "minLength" => 4, "maxLength" => 3 }
          ],
          "tokenizer" => { "kind" => "standard" }
        })
        }.to raise_error(CipherStash::Client::Error::InternalError, "The ngram filter min length must be less than or equal to the max length")
    end

    it "splits text into ngrams using min length of 3 and max length of 8" do
      tokenizer =
        CipherStash::Analysis::TextProcessor.new({
          "tokenFilters" => [
            { "kind" => "downcase" },
            { "kind" => "ngram", "minLength" => 3, "maxLength" => 8 }
          ],
         "tokenizer" => { "kind" => "standard" }
        })
      result = tokenizer.perform("Example filter")

      expect(result).to eq([
        "exa",
        "xam",
        "amp",
        "mpl",
        "ple",
        "exam",
        "xamp",
        "ampl",
        "mple",
        "examp",
        "xampl",
        "ample",
        "exampl",
        "xample",
        "example",
        "fil",
        "ilt",
        "lte",
        "ter",
        "filt",
        "ilte",
        "lter",
        "filte",
        "ilter",
        "filter"
      ])
    end
  end
end
