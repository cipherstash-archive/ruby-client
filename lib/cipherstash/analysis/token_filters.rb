module CipherStash
  module Analysis
    module TokenFilters
      class Base
        def initialize(opts = {})
          @opts = opts
        end
      end

      class Downcase < Base
        def perform(str_or_array)
          Array(str_or_array).map(&:downcase)
        end
      end

      class NGram < Base
        def perform(str_or_array)
          token_length = @opts["tokenLength"] || 3
          Array(str_or_array).flat_map do |token|
            [].tap do |out|
              token.chars().each_slice(token_length) do |slice|
                out << slice.join
              end
            end
          end
        end
      end
    end
  end
end

