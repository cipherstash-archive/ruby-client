module CipherStash
  class Client
    # Hash helper methods.
    #
    # @private
    module HashHelper
      def symbolize_keys(h)
        Hash[h.map do |k, v|
          [k.to_sym, v.is_a?(Hash) ? symbolize_keys(v) : v]
        end]
      end
    end
  end
end
