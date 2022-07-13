require_relative "./bloom_filter"

module CipherStash
    class Index
      # Implementation of the dynamic-filter-match index
      #
      # @private
      class DynamicFilterMatch < Index
        INDEX_OPS = {
          "match" => -> (idx, s) do
            filter = BloomFilter.new(idx.meta_settings["$filterKey"], idx.mapping_settings)

            bits = idx.text_processor.perform(s)
              .reduce(filter) { |filter, term| filter.add(term) }
              .bits
              .to_a

            [{ indexId: idx.binid, filter: { bits: bits } }]
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
            filter = BloomFilter.new(meta_settings["$filterKey"], mapping_settings)

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
