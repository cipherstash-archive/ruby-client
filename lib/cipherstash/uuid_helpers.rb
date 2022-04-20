module CipherStash
  # Some quick helpers to transmute UUIDs between the various forms we use.
  #
  # @private
  module UUIDHelpers
    def self.uuid_from_blob(blob)
      blob.unpack("H*").first.scan(/^(.{8})(.{4})(.{4})(.{4})(.*)$/).join("-")
    end

    def self.blob_from_uuid(uuid)
      [uuid.gsub("-", "")].pack("H*")
    end

    def self.included(mod)
      mod.extend(self)
    end
  end
end
