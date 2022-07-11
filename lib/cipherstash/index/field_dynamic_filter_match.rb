require_relative "./bloom_filter"

module CipherStash
    class Index
      # Implementation for the 'field-dynamic-filter-match' index type
      #
      # @private
      class FieldDynamicFilterMatch < Index
        INDEX_OPS = {
          "match" => -> (idx, f, s) do
            filter = BloomFilter.new([idx.meta_settings["$prfKey"]].pack("H*"))

            bits = idx.text_processor.perform(s)
              .map { |t| idx.ore_encrypt("#{f}:#{t}").to_s }
              .reduce(filter) { |filter, term| filter.add(term) }
              .bits
              .to_a

            { indexId: idx.binid, filter: { bits: bits } }
          end,
        }

        def analyze(uuid, record)
          blid = blob_from_uuid(uuid)

          raw_terms = collect_string_fields(record)

          if raw_terms == []
            nil
          else
            filter = BloomFilter.new([meta_settings["$prfKey"]].pack("H*"))
            bits = raw_terms
              .map { |f, s| text_processor.perform(s).map { |b| "#{f}:#{b}" } }
              .flatten
              .uniq
              .map { |t| ore_encrypt(t).to_s }
              .reduce(filter) { |filter, term| filter.add(term) }
              .bits
              .to_a

            { indexId: binid, terms: [{ bits: bits, link: blid }] }
          end
        end
      end
    end
  end
