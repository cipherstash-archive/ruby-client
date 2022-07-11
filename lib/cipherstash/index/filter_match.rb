require_relative "./bloom_filter"

module CipherStash
    class Index
      # Implementation for the 'filter-match' index type
      #
      # @private
      class FilterMatch < Index
        INDEX_OPS = {
          "match" => -> (idx, s) do
            filter = BloomFilter.new(
              [idx.meta_settings["$filterKey"]].pack("H*"),
              idx.mapping_settings
            )

            bits = idx.text_processor.perform(s)
              .reduce(filter) { |filter, term| filter.add(term) }
              .bits
              .to_a

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
              .reduce(filter) { |filter, term| filter.add(term) }
              .bits
              .to_a

            { indexId: binid, terms: [{ bits: bits, link: blid }] }
          end
        end
      end
    end
  end
