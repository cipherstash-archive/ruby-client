module CipherStash
  class Index
    # Implementation for the 'match' index type
    #
    # @private
    class Match < Index
      INDEX_OPS = {
        "match" => -> (idx, s) do
          id = UUIDHelpers.blob_from_uuid(idx.id)
          idx.text_processor.perform(s).map { |t| { indexId: id, exact: { term: [idx.ore_encrypt(t).to_s] } } }
        end,
      }

      def orderable?
        false
      end

      def analyze(uuid, record)
        blid = blob_from_uuid(uuid)

        field_names = @settings["mapping"]["fields"]
        raw_terms = field_names.map { |n| record[n] }

        terms = raw_terms.map { |s| text_processor.perform(s) }.flatten

        { indexId: blob_from_uuid(@id), terms: terms.map { |t| { term: [ore_encrypt(t).to_s], link: blid } } }
      end
    end
  end
end
