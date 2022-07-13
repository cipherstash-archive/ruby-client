require_relative "./bloom_filter"

module CipherStash
    class Index
      # Implementation for the 'field-dynamic-filter-match' index type
      #
      # @private
      class FieldDynamicFilterMatch < Index
        INDEX_OPS = {
          "match" => -> (idx, field, s) do
            filter = BloomFilter.new(idx.meta_settings["$filterKey"], idx.mapping_settings)

            bits = idx.text_processor.perform(s)
              .reduce(filter) { |filter, term| filter.add("#{field}:#{term}") }
              .bits
              .to_a

            [{ indexId: idx.binid, filter: { bits: bits } }]
          end,
        }

        def analyze(uuid, record)
          blid = blob_from_uuid(uuid)

          raw_terms = collect_string_fields(record)

          if raw_terms == []
            nil
          else
            filter = BloomFilter.new(meta_settings["$filterKey"], mapping_settings)

            bits = raw_terms
              .map { |f, s| text_processor.perform(s).map { |b| "#{f}:#{b}" } }
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
