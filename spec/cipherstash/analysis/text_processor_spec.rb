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
