module CipherStash
  class Index
    # Implementation for the 'field-dynamic-match' index type
    #
    # @private
    class FieldDynamicMatch < Index
      INDEX_OPS = {
        "match" => -> (idx, f, s) do
          id = UUIDHelpers.blob_from_uuid(idx.id)
          idx.text_processor.perform(s).map { |t| { indexId: id, exact: { term: [idx.ore_encrypt("#{f}:#{t}").to_s] } } }
        end,
      }

      def analyze(uuid, record)
        blid = blob_from_uuid(uuid)

        raw_terms = collect_string_fields(record)

        if raw_terms.all?(&:nil?)
          return nil
        end

        terms = raw_terms.map { |f, s| text_processor.perform(s).map { |b| "#{f}:#{b}" } }.flatten

        { indexId: blob_from_uuid(@id), terms: terms.map { |t| { term: [ore_encrypt(t).to_s], link: blid } } }
      end
    end
  end
end
