module CipherStash
  # Some quick helpers to transmute UUIDs between the various forms we use.
  #
  # @private
  module UUIDHelpers
    module ModuleMethods
      def uuid_from_blob(blob)
        blob.unpack("H*").first.scan(/^(.{8})(.{4})(.{4})(.{4})(.*)$/).join("-")
      end

      def blob_from_uuid(uuid)
        [uuid.gsub("-", "")].pack("H*")
      end
    end

    extend ModuleMethods

    def self.included(mod)
      mod.include(ModuleMethods)
    end
  end
end
