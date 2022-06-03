module CipherStash
  class Index
    # Implementation of the dynamic-match index
    #
    # @private
    class DynamicMatch < Index
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
        raw_terms = collect_string_fields(record).map(&:last)

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
