module CipherStash
  class Index
    # Implementation for the 'match' index type
    #
    # @private
    class OreMatch < Index
      INDEX_OPS = {
        "match" => -> (idx, s) do
          idx.text_processor.perform(s).map { |t| { indexId: idx.binid, exact: { term: [idx.ore_encrypt(t).to_s] } } }
        end,
      }

      def orderable?
        false
      end

      def analyze(uuid, record)
        blid = blob_from_uuid(uuid)

        field_names = @settings["mapping"]["fields"]
        raw_terms = field_names.map { |n| nested_lookup(record, n) }.compact

        if raw_terms == []
          nil
        else
          terms = raw_terms.map { |s| text_processor.perform(s) }.flatten.uniq
          { indexId: binid, terms: terms.map { |t| { term: [ore_encrypt(t).to_s], link: blid } } }
        end
      end
    end
  end
end
