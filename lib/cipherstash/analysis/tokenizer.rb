module CipherStash
  module Analysis
    module Tokenizer
      class Standard
        def perform(str)
          str.split(/\s+/)
        end
      end
    end
  end
end

