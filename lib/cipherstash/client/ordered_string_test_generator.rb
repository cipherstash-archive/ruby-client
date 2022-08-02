require "securerandom"
require "json"

require_relative "../index"

module CipherStash
  class Client
    # Generates test cases for orderable strings that can be used in automated tests in other
    # clients (e.g. StashRS). Test cases are written to JSON files.
    #
    # Example usage in StashRS:
    # https://github.com/cipherstash/cipherstash-rs/blob/00ff66d712e6f36a89acfa731b680a69789647cf/packages/cipherstash-client/src/indexer/mapping_indexer.rs#L537-L570
    #
    # @private
    class OrderedStringTestGenerator
      # The number of test cases to generate per test file. This number is arbitrary. 100 seems good
      # because GitHub is willing to display the output files in diffs in PRs, but will require
      # pulling branches down for larger numbers of test cases.
      NUM_TEST_CASES = 100

      # Max character code for ASCII characters in randomly generated strings in test data.
      ASCII_CHAR_CODE_MAX = 127

      # The max length of randomly generated strings in test data. This number is also somewhat
      # arbitrary. The first 80 ASCII characters are considered for ordering, so we want some
      # strings with a length of at least 80. 200 seems good because this will also test lengths
      # beyond what actually gets indexed for ordering but doesn't bloat the test files too much.
      MAX_STRING_LENGTH = 200

      def run
        create_orderise_string_test_cases
        create_string_comparison_test_cases
      end

      private

      def random_ascii_string
        (0..rand(MAX_STRING_LENGTH - 1)).map { rand(ASCII_CHAR_CODE_MAX + 1).chr }.join
      end

      def index
        id = SecureRandom.uuid
        settings = {
          "meta" => {
            "$indexId" => id,
            "$indexName" => "titleSort",
            "$prfKey" => SecureRandom.hex(16),
            "$prpKey" => SecureRandom.hex(16),
          },
          "mapping" => {
            "kind" => "range",
            "field" => "title",
            "fieldType"=>"string",
          }
        }
        schema_versions = {:first=>0, :last=>0, :searchable=>true}

        CipherStash::Index.generate(id, settings, schema_versions)
      end

      def write_cases_to_file(filename, test_cases)
        File.write(filename, JSON.pretty_generate(test_cases))
        puts "Created ./" + filename
      end

      def create_orderise_string_test_cases
        orderise_string_cases = (0..(NUM_TEST_CASES - 1)).map do
          str = random_ascii_string
          output = index.__send__ :orderise_string, str
          {input: str, output: output}
        end

        write_cases_to_file("orderise_string_test_cases.json", orderise_string_cases)
      end

      def create_string_comparison_test_cases
        string_comparison_cases = (0..(NUM_TEST_CASES - 1)).map do
          str_a = random_ascii_string
          terms_a = index.__send__ :orderise_string, str_a

          str_b = random_ascii_string
          terms_b = index.__send__ :orderise_string, str_b

          output = case terms_a <=> terms_b
            when -1
              "<"
            when 0
              "=="
            when 1
              ">"
            end

          {input: [str_a, str_b], output: output}
        end

        write_cases_to_file("string_comparison_test_cases.json", string_comparison_cases)
      end
    end
  end
end
