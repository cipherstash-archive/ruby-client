require_relative "./bloom_filter"

module CipherStash
    class Index
      # Implementation of the dynamic-filter-match index
      #
      # @private
      class DynamicFilterMatch < Index
        INDEX_OPS = {
          "match" => -> (idx, s) do
            terms = idx.text_processor.perform(s)
            filter = BloomFilter.new(idx.meta_settings["$filterKey"], idx.mapping_settings).add(terms)

            [{ indexId: idx.binid, filter: { bits: filter.to_a } }]
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
            filter = BloomFilter.new(meta_settings["$filterKey"], mapping_settings).add(terms)

            { indexId: binid, terms: [{ bits: filter.to_a, link: blid }] }
          end
        end
      end
    end
  end
