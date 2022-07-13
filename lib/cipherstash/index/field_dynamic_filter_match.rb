require_relative "./bloom_filter"

module CipherStash
    class Index
      # Implementation for the 'field-dynamic-filter-match' index type
      #
      # @private
      class FieldDynamicFilterMatch < Index
        INDEX_OPS = {
          "match" => -> (idx, field, s) do
            terms = idx.text_processor.perform(s).map { |term| "#{field}:#{term}" }
            filter = BloomFilter.new(idx.meta_settings["$filterKey"], idx.mapping_settings).add(terms)

            [{ indexId: idx.binid, filter: { bits: filter.to_a } }]
          end,
        }

        def analyze(uuid, record)
          blid = blob_from_uuid(uuid)

          raw_terms = collect_string_fields(record)

          if raw_terms == []
            nil
          else
            terms = raw_terms
              .map { |f, s| text_processor.perform(s).map { |b| "#{f}:#{b}" } }
              .flatten
              .uniq

            filter = BloomFilter.new(meta_settings["$filterKey"], mapping_settings).add(terms)

            { indexId: binid, terms: [{ bits: filter.to_a, link: blid }] }
          end
        end
      end
    end
  end
