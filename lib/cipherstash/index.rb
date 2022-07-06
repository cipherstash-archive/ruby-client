require "ore-rs"

require_relative "./uuid_helpers"
require_relative "./analysis/text_processor"

require_relative "./index/exact"
require_relative "./index/range"
require_relative "./index/ore_match"
require_relative "./index/dynamic_ore_match"
require_relative "./index/field_dynamic_ore_match"
require_relative "./index/field_dynamic_exact"

module CipherStash
  # Represents an index on a CipherStash collection.
  #
  # @private
  class Index
    include UUIDHelpers

    def self.generate(id, settings, schema_versions)
      case settings["mapping"]["kind"]
      when "exact"
        Exact.new(id, settings, schema_versions)
      when "range"
        Range.new(id, settings, schema_versions)
      when "match"
        OreMatch.new(id, settings, schema_versions)
      when "dynamic-match"
        DynamicOreMatch.new(id, settings, schema_versions)
      when "field-dynamic-match"
        FieldDynamicOreMatch.new(id, settings, schema_versions)
      when "field-dynamic-exact"
        FieldDynamicExact.new(id, settings, schema_versions)
      else
        raise Error::InvalidSchemaError, "Unknown index kind #{settings["mapping"]["kind"].inspect}"
      end
    end

    # @return [String] index UUID in human-readable form
    attr_reader :uuid

    # @return [String] the contents of the 'meta' section of the index's settings
    def meta_settings
      @settings["meta"]
    end

    # @return [Integer] the first (earliest) version of the collection schema in which this index appears
    attr_reader :first_schema_version

    # @return [Integer] the last (most recent) version of the collection schema in which this index appears
    attr_reader :last_schema_version

    # Creates a new index from the decrypted settings.
    def initialize(uuid, settings, schema_versions)
      unless is_uuid?(uuid)
        raise Error::InternalError, "Invalid UUID passed to Index.new: #{uuid.inspect}"
      end
      unless uuid == settings["meta"]["$indexId"]
        raise Error::InternalError, "Provided UUID does not match UUID in settings (#{uuid} != #{settings["meta"]["$indexId"]})"
      end
      @uuid, @settings = uuid, settings
      @first_schema_version, @last_schema_version, @is_searchable = schema_versions[:first], schema_versions[:last], schema_versions[:searchable]
    end

    # @return [String] index ID in "binary" form
    def binid
      @binid ||= blob_from_uuid(@uuid)
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
    # @return [Documents::Vector, NilClass] either a vector of encrypted terms to insert into the data store, or `NilClass` if we couldn't find anything to index.
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

    # Is this index OK to be queried yet, or is it still pending re-indexing?
    def searchable?
      @is_searchable
    end

    # Determine if the mapping of this index is compatible with the argument
    #
    # @param other [Hash<String, Object>] the mapping details to compare against
    #
    # @return [Boolean]
    #
    def ===(other)
      @settings["mapping"] === other[:mapping]
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

    def nested_lookup(record, path)
      k, r = path.split(".", 2)
      if r.nil?
        record[k]
      elsif record[k].is_a?(Hash)
        nested_lookup(record[k], r)
      else
        nil
      end
    end
  end
end
