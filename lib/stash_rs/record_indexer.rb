module StashRs
  class RecordIndexer
    def self.new(schema)
      pp schema
      _new(schema.to_cbor)
    end

    def encrypt(uuid, data)
      _encrypt(Record.new(uuid, data))
    end
  end
end
