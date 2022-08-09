require_relative "./bloom_filter"

module CipherStash
    class Index
      # Implementation for the 'filter-match' index type
      #
      # @private
      class FilterMatch < Index
        INDEX_OPS = {
          "match" => -> (idx, s) do
            terms = idx.text_processor.perform(s)
            filter = BloomFilter.new(idx.meta_settings["$filterKey"], idx.mapping_settings).add(terms)

            [{ indexId: idx.binid, filter: { bits: filter.to_a } }]
          end,
        }

        def self.supported_kinds
          ["filter-match"]
        end

        def self.meta(name)
          self.filter_meta(name)
        end

        def orderable?
          false
        end

        def self.uniqueness_supported?
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
            filter = BloomFilter.new(meta_settings["$filterKey"], mapping_settings).add(terms)

            { indexId: binid, terms: [{ bits: filter.to_a, link: blid }] }
          end
        end
      end
    end
  end
