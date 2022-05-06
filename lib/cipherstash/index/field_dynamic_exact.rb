module CipherStash
  class Index
    # Implementation for the 'field-dynamic-exact' index type
    #
    # @private
    class FieldDynamicExact < Index
      INDEX_OPS = {
        "eq" => -> (idx, f, s) do
          id = UUIDHelpers.blob_from_uuid(idx.id)
          [{ indexId: id, exact: { term: [idx.ore_encrypt("#{f}:#{s}").to_s] } }]
        end,
      }

      def analyze(uuid, record)
        blid = blob_from_uuid(uuid)

        raw_terms = collect_string_fields(record)

        if raw_terms == []
          nil
        else
          terms = raw_terms.map { |f, s| "#{f}:#{s}" }
          { indexId: blob_from_uuid(@id), terms: terms.map { |t| { term: [ore_encrypt(t).to_s], link: blid } } }
        end
      end
    end
  end
end
