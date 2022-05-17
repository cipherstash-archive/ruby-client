require "aws-sdk-core"
require "aws-sdk-sts"

module CipherStash
  class Client
    # Responsible for retrieving AWS credentials via federation (AssumeRoleWithWebIdentity)
    #
    # @private
    class AwsFederatedCredentials
      EXPIRY_GRACE_PERIOD_SECONDS = 120

      def initialize(profile, role_arn, region, logger)
        @profile, @role_arn, @region, @logger = profile, role_arn, region, logger

        @credentials = nil
      end

      def credentials
        if expired?
          acquire_new_creds
        end

        Aws::Credentials.new(@credentials.access_key_id, @credentials.secret_access_key, @credentials.session_token)
      end

      def expired?
        if @credentials.nil?
          @logger.debug("AwsFederatedCredentials#expired?") { "@credentials is nil" }
          true
        else
          @logger.debug("AwsFederatedCredentials#expired?") { "Expiry check; expiration=#{@credentials.expiration.inspect}" }
          Time.now + EXPIRY_GRACE_PERIOD_SECONDS > @credentials.expiration
        end
      end

      private

      def sts_client
        @sts_client ||= Aws::STS::Client.new(region: @region)
      end

      def acquire_new_creds
        res = sts_client.assume_role_with_web_identity(
          role_arn: @role_arn,
          role_session_name: "ruby-client",
          web_identity_token: @profile.with_access_token[:access_token]
        )

        @credentials = res.credentials

        @logger.debug("AwsFederatedCredentials#fresh_credentials") { "returning creds; new expiry #{@credentials.expiration}" }
      end
    end
  end
end
