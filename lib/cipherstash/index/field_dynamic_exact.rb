module CipherStash
  class Index
    # Implementation for the 'field-dynamic-exact' index type
    #
    # @private
    class FieldDynamicExact < Index
      INDEX_OPS = {
        "eq" => -> (idx, f, s) do
          [{ indexId: idx.binid, exact: { term: [idx.ore_encrypt("#{f}:#{s}").to_s] } }]
        end,
      }

      def self.supported_kinds
        ["field-dynamic-exact"]
      end

      def self.meta(name)
        self.ore_meta(name)
      end

      def self.uniqueness_supported?
        false
      end

      def analyze(uuid, record)
        blid = blob_from_uuid(uuid)

        raw_terms = collect_string_fields(record)

        if raw_terms == []
          nil
        else
          terms = raw_terms.map { |f, s| "#{f}:#{s}" }.uniq
          { indexId: binid, terms: terms.map { |t| { term: [ore_encrypt(t).to_s], link: blid } } }
        end
      end
    end
  end
end
