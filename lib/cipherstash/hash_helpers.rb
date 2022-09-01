module CipherStash
  # Hash helper methods.
  #
  # @private
  module HashHelpers
    def nested_set(h, k, v)
      f, r = k.split(".", 2)
      if r.nil?
        if v.nil?
          h.delete(k)
        else
          h[k] = v
        end
      else
        h[f] ||= {}
        h[f] = nested_set(h[f], r, v)
      end
      h
    end

    def symbolize_keys(h)
      Hash[h.map do |k, v|
        [k.to_sym, v.is_a?(Hash) ? symbolize_keys(v) : v]
      end]
    end
  end
end
