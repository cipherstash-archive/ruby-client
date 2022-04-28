require "ore-rs"

require_relative "./uuid_helpers"
require_relative "./analysis/text_processor"

require_relative "./index/exact"
require_relative "./index/range"
require_relative "./index/match"
require_relative "./index/dynamic_match"
require_relative "./index/field_dynamic_match"

module CipherStash
  # Represents an index on a CipherStash collection.
  #
  # @private
  class Index
    include UUIDHelpers

    def self.generate(id, settings)
      case settings["mapping"]["kind"]
      when "exact"
        Exact.new(id, settings)
      when "range"
        Range.new(id, settings)
      when "match"
        Match.new(id, settings)
      when "dynamic-match"
        DynamicMatch.new(id, settings)
      when "field-dynamic-match"
        FieldDynamicMatch.new(id, settings)
      else
        raise Error::InvalidSchemaError, "Unknown index kind #{settings["mapping"]["kind"].inspect}"
      end
    end

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
      self.class::INDEX_OPS.key?(op)
    end

    # Does this index support ordering?
    #
    # @return [bool]
    #
    def orderable?
      # Most indexes don't support ordering; it's an opt-in thing for those
      # that do
      false
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
      raise RuntimeError, "Virtual method analyze called"
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
      op_fn = self.class::INDEX_OPS[op]
      if op_fn.nil?
        raise Error::InvalidQuery, "Unknown operator #{op.inspect}"
      end

      op_fn.call(self, *args)
    end

    # Encrypt the given term using ORE
    #
    # @param term [Object] the plaintext term to encrypt
    #
    def ore_encrypt(term)
      ore.encrypt(term)
    end

    # Return the text processor for this index
    def text_processor
      @text_processor ||= Analysis::TextProcessor.new(@settings["mapping"])
    end

    private

    def ore
      @ore ||= begin
                 ORE::AES128.new([@settings["meta"]["$prfKey"]].pack("H*"), [@settings["meta"]["$prpKey"]].pack("H*"), 64, 8)
               end
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
