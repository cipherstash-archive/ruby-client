module CipherStash
  class Index
    # Implementation for the 'exact' index type
    #
    # @private
    class Exact < Index
      INDEX_OPS = {
        "eq" => -> (idx, t) do
          [{ indexId: idx.binid, exact: { term: [idx.ore_encrypt(t).to_s] } }]
        end,
      }

      def self.supported_kinds
        ["exact"]
      end

      def self.meta(name)
        self.ore_meta(name)
      end

      def self.mapping(base_settings, schema)
        base_settings.merge("fieldType" => schema["type"][base_settings["field"]])
      end

      def orderable?
        false
      end

      def analyze(uuid, record)
        blid = blob_from_uuid(uuid)

        field_name = @settings["mapping"]["field"]
        term = nested_lookup(record, field_name)

        if term.nil?
          nil
        else
          { indexId: binid, terms: [{ term: [ore_encrypt(term).to_s], link: blid }] }
        end
      end
    end
  end
end
