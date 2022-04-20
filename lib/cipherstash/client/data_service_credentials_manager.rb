module CipherStash
  class Client
    # Responsible for making sure we always have fresh credz
    #
    # @private
    class DataServiceCredentialsManager
      def initialize(profile, logger)
        @profile, @logger = profile, logger
        @idp_config = @profile.identity_provider_config
      end

      def fresh_credentials
        # Hard-coded token isn't great, but it's easy if it works!
        unless (token = @idp_config["accessToken"]).nil?
          return { access_token: token }
        end

        if @cached_token.nil?
          @cached_token = read_cached_token
        end

        # No automatic refresh of tokens for now; need to use `stash login`
        return { access_token: @cached_token["accessToken"] }
      end

      private

      def read_cached_token
        @cached_token = @profile.read_cached_token
      end
    end
  end
end
