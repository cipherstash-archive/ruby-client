require "ore-rs"

require_relative "./uuid_helpers"
require_relative "./analysis/text_processor"

module CipherStash
  # Represents an index on a CipherStash collection.
  #
  # @private
  class Index
    include UUIDHelpers

    # @return [String] index UUID in human-readable form
    attr_reader :id

    # Creates a new index from the decrypted settings.
    def initialize(id, settings)
      @id, @settings = id, settings
    end

    # The index's name, as defined in the schema
    def name
      @settings["meta"]["$indexName"]
    end

    # Does this index support the specified operator?
    #
    # @return [bool]
    #
    def supports?(op)
      (INDEX_OPS[@settings["mapping"]["kind"]] || {}).key?(op)
    end

    # Does this index support ordering?
    #
    # @return [bool]
    #
    def orderable?
      @settings["mapping"]["kind"] == "range"
    end

    # Examine the given record and send back index vectors.
    #
    # @param id [String] human-readable UUID of the record that is being
    #   analyzed.
    #
    # @param record [Object] the record data to analyze.
    #
    # @return [Documents::Vector]
    #
    def analyze(id, record)
      id = blob_from_uuid(id)

      case @settings["mapping"]["kind"]
      when "exact", "range"
        scalar_vector(id, record)
      when "match"
        match_vector(id, record)
      when "dynamic-match"
        dynamic_match_vector(id, record)
      when "field-dynamic-match"
        field_dynamic_match_vector(id, record)
      else
        $stderr.puts "Not indexing #{@settings["mapping"]["kind"]} indexes yet"
      end
    end

    # Figure out the constraints to apply to a query
    #
    # @param op [String] the operator (eq, lt, match, etc)
    #
    # @param term [Object] the plaintext value of the term associated with the operator
    #
    # @return [Array<Hash>]
    #
    def generate_constraints(op, *args)
      INDEX_OPS[@settings["mapping"]["kind"]][op].call(self, *args)
    end

    # Encrypt the given term using ORE
    #
    # @param term [Object] the plaintext term to encrypt
    #
    def ore_encrypt(term)
      ore.encrypt(term)
    end

    def text_processor
      @text_processor ||= Analysis::TextProcessor.new(@settings["mapping"])
    end

    INDEX_OPS = {
      "exact" => {
        "eq" => -> (idx, t) do
          [{ indexId: UUIDHelpers.blob_from_uuid(idx.id), exact: { term: idx.ore_encrypt(t).to_s } }]
        end,
      },
      "range" => {
        "eq" => -> (idx, t) do
          et = idx.ore_encrypt(t)
          [{ indexId: UUIDHelpers.blob_from_uuid(idx.id), range: { lower: et.to_s, upper: et.to_s } }]
        end,
        "lt" => -> (idx, t) do
          et = idx.ore_encrypt(..t-1)
          [{ indexId: UUIDHelpers.blob_from_uuid(idx.id), range: { lower: et.first.to_s, upper: et.last.to_s } }]
        end,
        "lte" => -> (idx, t) do
          et = idx.ore_encrypt(..t)
          [{ indexId: UUIDHelpers.blob_from_uuid(idx.id), range: { lower: et.first.to_s, upper: et.last.to_s } }]
        end,
        "gt" => -> (idx, t) do
          et = idx.ore_encrypt(t+1..)
          [{ indexId: UUIDHelpers.blob_from_uuid(idx.id), range: { lower: et.first.to_s, upper: et.last.to_s } }]
        end,
        "gte" => -> (idx, t) do
          et = idx.ore_encrypt(t..)
          [{ indexId: UUIDHelpers.blob_from_uuid(idx.id), range: { lower: et.first.to_s, upper: et.last.to_s } }]
        end,
        "between" => -> (idx, min, max) do
          et = idx.ore_encrypt(min..max)
          [{ indexId: UUIDHelpers.blob_from_uuid(idx.id), range: { lower: et.first.to_s, upper: et.last.to_s } }]
        end,
      },
      "match" => {
        "match" => -> (idx, s) do
          id = UUIDHelpers.blob_from_uuid(idx.id)
          idx.text_processor.perform(s).map { |t| { indexId: id, exact: { term: idx.ore_encrypt(t).to_s } } }
        end,
      },
      "dynamic-match" => {
        "match" => -> (idx, s) do
          id = UUIDHelpers.blob_from_uuid(idx.id)
          idx.text_processor.perform(s).map { |t| { indexId: id, exact: { term: idx.ore_encrypt(t).to_s } } }
        end,
      },
      "field-dynamic-match" => {
        "match" => -> (idx, f, s) do
          id = UUIDHelpers.blob_from_uuid(idx.id)
          idx.text_processor.perform(s).map { |t| { indexId: id, exact: { term: idx.ore_encrypt("#{f}:#{t}").to_s } } }
        end,
      },
    }

    private_constant :INDEX_OPS

    private

    def ore
      @ore ||= begin
                 ORE::AES128.new([@settings["meta"]["$prfKey"]].pack("H*"), [@settings["meta"]["$prpKey"]].pack("H*"), 64, 8)
               end
    end

    def scalar_vector(id, record)
      field_name = @settings["mapping"]["field"]
      term = record[field_name]

      if term.nil?
        $stderr.puts "Did not find value for #{field_name.inspect} in #{record.inspect}"
      else
        { indexId: blob_from_uuid(@id), terms: [{ term: ore_encrypt(term).to_s, link: id }] }
      end
    end

    def match_vector(id, record)
      field_names = @settings["mapping"]["fields"]
      raw_terms = field_names.map { |n| record[n] }

      terms = raw_terms.map { |s| text_processor.perform(s) }.flatten

      { indexId: blob_from_uuid(@id), terms: terms.map { |t| { term: ore_encrypt(t).to_s, link: id } } }
    end

    def dynamic_match_vector(id, record)
      raw_terms = collect_string_fields(record).map(&:last)

      terms = raw_terms.map { |s| text_processor.perform(s) }.flatten

      { indexId: blob_from_uuid(@id), terms: terms.map { |t| { term: ore_encrypt(t).to_s, link: id } } }
    end

    def field_dynamic_match_vector(id, record)
      raw_terms = collect_string_fields(record)

      terms = raw_terms.map { |f, s| text_processor.perform(s).map { |b| "#{f}:#{b}" } }.flatten

      { indexId: blob_from_uuid(@id), terms: terms.map { |t| { term: ore_encrypt(t).to_s, link: id } } }
    end

    def collect_string_fields(record, prefix = "")
      record.each_with_object([]) do |(k, v), a|
        if v.is_a?(String)
          a << ["#{prefix}#{k}", v]
        elsif v.is_a?(Hash)
          a.append(*collect_string_fields(v, "#{prefix}#{k}."))
        end
      end
    end
  end
end
