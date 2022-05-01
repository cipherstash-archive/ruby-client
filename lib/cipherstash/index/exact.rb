module CipherStash
  class Index
    # Implementation for the 'exact' index type
    #
    # @private
    class Exact < Index
      INDEX_OPS = {
        "eq" => -> (idx, t) do
          [{ indexId: UUIDHelpers.blob_from_uuid(idx.id), exact: { term: [idx.ore_encrypt(t).to_s] } }]
        end,
      }

      def orderable?
        false
      end

      def analyze(uuid, record)
        blid = blob_from_uuid(uuid)

        field_name = @settings["mapping"]["field"]
        term = record[field_name]

        if term.nil?
          $stderr.puts "Did not find value for #{field_name.inspect} in #{record.inspect}"
          nil
        else
          { indexId: blob_from_uuid(@id), terms: [{ term: [ore_encrypt(term).to_s], link: blid }] }
        end
      end
    end
  end
end
