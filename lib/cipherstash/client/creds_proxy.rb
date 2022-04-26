module CipherStash
  class Client
    # Tiny little class to handle the "do we need to refresh yet?" logic
    #
    # @private
    class CredsProxy
      def initialize(&blk)
        @blk = blk
      end

      def method_missing(m, *args)
        @blk.call.__send__(m, *args)
      end
    end
  end
end
