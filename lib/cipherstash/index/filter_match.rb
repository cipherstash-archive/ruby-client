module CipherStash
    class Index
      # Implementation for the 'filter-match' index type
      #
      # @private
      class FilterMatch < Index
        INDEX_OPS = {
          "match" => -> (idx, s) do
            filter = BloomFilter.new([meta_settings["$prfKey"]].pack("H*"))

            bits = idx.text_processor.perform(s)
              .map { |t| ore_encrypt(t).to_s }
              .reduce(filter) { |filter, term| filter.add(term) }
              .bits # TODO: should bits be a list rather than set?

            { indexId: idx.binid, filter: { bits: bits } }
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
            filter = BloomFilter.new([meta_settings["$prfKey"]].pack("H*"))
            bits = raw_terms
              .map { |s| text_processor.perform(s) }
              .flatten
              .uniq
              .map { |t| ore_encrypt(t).to_s }
              .reduce(filter) { |filter, term| filter.add(term) }
              .bits # TODO: should bits be a list rather than set?

            { indexId: binid, terms: { bits: bits, link: blid } }
          end
        end
      end
    end
  end
