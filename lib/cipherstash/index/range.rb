module CipherStash
  class Index
    # Implementation for the 'range' index type
    #
    # @private
    class Range < Index
      INDEX_OPS = {
        "eq" => -> (idx, t) do
          et = idx.ore_encrypt(t)
          [{ indexId: UUIDHelpers.blob_from_uuid(idx.id), range: { lower: [et.to_s], upper: [et.to_s] } }]
        end,
        "lt" => -> (idx, t) do
          et = idx.ore_encrypt(..t-1)
          [{ indexId: UUIDHelpers.blob_from_uuid(idx.id), range: { lower: [et.first.to_s], upper: [et.last.to_s] } }]
        end,
        "lte" => -> (idx, t) do
          et = idx.ore_encrypt(..t)
          [{ indexId: UUIDHelpers.blob_from_uuid(idx.id), range: { lower: [et.first.to_s], upper: [et.last.to_s] } }]
        end,
        "gt" => -> (idx, t) do
          et = idx.ore_encrypt(t+1..)
          [{ indexId: UUIDHelpers.blob_from_uuid(idx.id), range: { lower: [et.first.to_s], upper: [et.last.to_s] } }]
        end,
        "gte" => -> (idx, t) do
          et = idx.ore_encrypt(t..)
          [{ indexId: UUIDHelpers.blob_from_uuid(idx.id), range: { lower: [et.first.to_s], upper: [et.last.to_s] } }]
        end,
        "between" => -> (idx, min, max) do
          et = idx.ore_encrypt(min..max)
          [{ indexId: UUIDHelpers.blob_from_uuid(idx.id), range: { lower: [et.first.to_s], upper: [et.last.to_s] } }]
        end,
      }

      def orderable?
        true
      end

      def analyze(uuid, record)
        blid = blob_from_uuid(uuid)

        field_name = @settings["mapping"]["field"]
        base_term = record[field_name]

        term = if @settings["mapping"]["fieldType"] == "string"
                 orderise_string(base_term)
               else
                 [base_term]
               end

        if term.nil?
          $stderr.puts "Did not find value for #{field_name.inspect} in #{record.inspect}"
        else
          { indexId: blob_from_uuid(@id), terms: [{ term: term.map { |t| ore_encrypt(t).to_s }, link: blid }] }
        end
      end

      private

      def orderise_string(s)
        unless s.force_encoding("US-ASCII").valid_encoding?
          raise Client::Error::InvalidRecordError, "Can only order strings that are pure ASCII"
        end

        # This all very much relies on ASCII character numbering.  A copy of `ascii`(7)
        # up on a convenient terminal may assist in understanding what's going
        # on here.
        n = s
          # We care not for your capitals!
          .downcase
          # Any group of rando characters sort at the end
          .gsub(/[^a-z0-9 ]+/, '~')
          # Any amount of whitespace comes immediately after letters
          .gsub(/[[:space:]]+/, '{')
          # Numbers come after spaces
          .gsub(/[0-9]/, '|')
          .each_char
          # 'a' => 1, 'b' => 2, ..., 'z' => 27, '{' => 28, '|' => 29,
          # '}' => 30 (unused), '~' => 31.  0 is kept as "no character" so
          # that short strings sort before longer ones.
          .map { |c| c.ord - 96 }
          # Turn the whole thing into one giant number, with each character
          # occupying five bits of said number.
          .inject(0) { |i, c| (i << 5) + c }

        # Now we need to turn the number into one whose in-memory representation
        # has a length in bits that is a multiple of 64.  This is to ensure that
        # the first character has the most-significant bits possible, so it
        # sorts the highest.
        n = n << (64 - (s.length * 5) % 64)

        # And now we can turn all that gigantic mess into an array of terms
        [].tap do |terms|
          while n > 0
            terms.unshift(n % 2**64)
            n >>= 64
          end
        # Only six ORE ciphertexts can fit into the database
        end[0, 6]
      end
    end
  end
end
