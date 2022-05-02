module CipherStash
  class Client
    # Tiny little class to handle the "do we need to refresh yet?" logic
    #
    # @private
    class CredsProxy < BasicObject
      def initialize(provider, &blk)
        @provider, @blk = provider, blk
        @value = nil
      end

      def method_missing(m, *args)
        _refresh_value
        @value.__send__(m, *args)
      end

      private

      def _refresh_value
        if @value.nil? || @provider.expired?
          @value = @blk.call
        end

        if @value.nil?
          ::Kernel.raise Error::CredentialsFailure, "Could not get fresh credentials"
        end
      end
    end
  end
end
