require "ore-rs"

module CipherStash
  # Represents an index on a CipherStash collection.
  #
  # @private
  class Index
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

    # Figure out the constraints to apply to a query
    #
    # @param op [String] the operator (eq, lt, match, etc)
    #
    # @param term [Object] the plaintext value of the term associated with the operator
    #
    # @return [Array<Hash>]
    #
    def generate_constraints(op, term)
      INDEX_OPS[@settings["mapping"]["kind"]][op].call(self, term)
    end

    # Encrypt the given term using ORE
    #
    # @param term [Object] the plaintext term to encrypt
    #
    def ore_encrypt(term)
      ore.encrypt(term)
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
      }
    }

    private_constant :INDEX_OPS

    private

    def ore
      @ore ||= begin
                 ORE::AES128.new([@settings["meta"]["$prfKey"]].pack("H*"), [@settings["meta"]["$prpKey"]].pack("H*"), 64, 8)
               end
    end
  end
end
