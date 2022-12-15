require_relative "./token_filters"
require_relative "./tokenizer"

module CipherStash
  module Analysis
    # General (but very simple) string processor
    # based on settings from a CipherStash collection schema
    #
    class TextProcessor
      # Creates a new string processor for the given field settings
      #
      # @param settings [Hash] the field settings
      #
      # ## Example
      #
      # Processor.new({
      #   "tokenFilters"=>[
      #     {"kind"=>"downcase"},
      #     {"kind"=>"ngram", "minLength"=>3, "maxLength"=>8}
      #   ],
      #   "tokenizer"=>{"kind"=>"standard"}
      # })
      #
      def initialize(settings)
        @token_filters = build_token_filters(settings["tokenFilters"])
        @tokenizer = build_tokenizer(settings["tokenizer"])
      end

      # Processes the given str and returns an array of tokens (the "Vector")
      #
      # @param str [String] the string to process
      # @return [String]
      #
      def perform(str)
        tokens = @tokenizer.perform(str)
        @token_filters.inject(tokens) do |result, stage|
          stage.perform(result)
        end
      end

      private
      def build_token_filters(array)
        array.map do |obj|
          case obj["kind"]
          when "downcase"
            TokenFilters::Downcase.new(obj)

          when "ngram"
            unless obj["minLength"].instance_of?(Integer) && obj["maxLength"].instance_of?(Integer)
              raise CipherStash::Client::Error::InternalError, "The values provided to the min and max length must be of type Integer."
            end

            unless obj["maxLength"] >= obj["minLength"]
                raise CipherStash::Client::Error::InternalError, "The ngram filter min length must be less than or equal to the max length"
            end

            TokenFilters::NGram.new(obj)

          else
            raise "Unknown token filter: '#{obj['kind']}'"
          end
        end
      end

      def build_tokenizer(obj)
        if obj["kind"] == "standard"
          Tokenizer::Standard.new
        else
          raise "Unknown tokenizer: '#{obj['kind']}'"
        end
      end
    end
  end
end
