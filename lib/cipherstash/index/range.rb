module CipherStash
  class Index
    # Implementation for the 'range' index type
    #
    # @private
    class Range < Index
      INDEX_OPS = {
        "eq" => -> (idx, t) do
          et = idx.ore_encrypt(t)
          [{ indexId: idx.binid, range: { lower: [et.to_s], upper: [et.to_s] } }]
        end,
        "lt" => -> (idx, t) do
          et = idx.ore_encrypt(..t-1)
          [{ indexId: idx.binid, range: { lower: [et.first.to_s], upper: [et.last.to_s] } }]
        end,
        "lte" => -> (idx, t) do
          et = idx.ore_encrypt(..t)
          [{ indexId: idx.binid, range: { lower: [et.first.to_s], upper: [et.last.to_s] } }]
        end,
        "gt" => -> (idx, t) do
          et = idx.ore_encrypt(t+1..)
          [{ indexId: idx.binid, range: { lower: [et.first.to_s], upper: [et.last.to_s] } }]
        end,
        "gte" => -> (idx, t) do
          et = idx.ore_encrypt(t..)
          [{ indexId: idx.binid, range: { lower: [et.first.to_s], upper: [et.last.to_s] } }]
        end,
        "between" => -> (idx, min, max) do
          et = idx.ore_encrypt(min..max)
          [{ indexId: idx.binid, range: { lower: [et.first.to_s], upper: [et.last.to_s] } }]
        end,
      }

      def self.supported_kinds
        ["range"]
      end

      def self.meta(name)
        self.ore_meta(name)
      end

      def self.mapping(base_settings, schema)
        base_settings.merge("fieldType" => schema["type"][base_settings["field"]])
      end

      def orderable?
        true
      end

      def analyze(uuid, record)
        blid = blob_from_uuid(uuid)

        field_name = @settings["mapping"]["field"]
        base_term = nested_lookup(record, field_name)

        if base_term.nil?
          return nil
        else
          terms = if @settings["mapping"]["fieldType"] == "string"
                    orderise_string(base_term)
                  else
                    [base_term]
                  end

          { indexId: binid, terms: [{ term: terms.map { |t| ore_encrypt(t).to_s }, link: blid }] }
        end
      end

      private

      def orderise_string(s)
        unless s.clone.force_encoding("US-ASCII").valid_encoding?
          raise Client::Error::InvalidRecordError, "Can only order strings that are pure ASCII"
        end

        # This all very much relies on ASCII character numbering.  A copy of `ascii`(7)
        # up on a convenient terminal may assist in understanding what's going
        # on here.

        # First up, let's transmogrify the string we were given into one that only contains
        # a controlled subset of characters, that we can easily map into a smaller numeric
        # space.
        s = s
          # We care not for your capitals!
          .downcase
          # Any group of rando characters sort at the end
          .gsub(/[^a-z0-9[:space:]]+/, '~')
          # Any amount of whitespace comes immediately after letters
          .gsub(/[[:space:]]+/, '{')
          # Numbers come after spaces
          .gsub(/[0-9]/, '|')

        # Next, we turn that string of characters into a "packed" number that represents the
        # whole string, but in a more compact form than would be used if each character took
        # up the full seven or eight bits used by regular ASCII.
        n = s
          .each_char
          # 'a' => 1, 'b' => 2, ..., 'z' => 27, '{' => 28, '|' => 29,
          # '}' => 30 (unused), '~' => 31.  0 is kept as "no character" so
          # that short strings sort before longer ones.
          .map { |c| c.ord - 96 }
          # Turn the whole thing into one giant number, with each character
          # occupying five bits of said number.
          .inject(0) { |i, c| (i << 5) + c }

        # Thirdly, we need to turn the number into one whose in-memory representation
        # has a length in bits that is a multiple of 64.  This is to ensure that
        # the first character has the most-significant bits possible, so it
        # sorts the highest.
        n = n << (64 - (s.length * 5) % 64)

        # And now, semi-finally, we can turn all that gigantic mess into an array of terms
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
