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

        @expires_at = nil
      end

      def credentials
        res = sts_client.assume_role_with_web_identity(
          role_arn: @role_arn,
          role_session_name: "ruby-client",
          web_identity_token: @profile.with_access_token[:access_token]
        )

        @expires_at = res.credentials.expiration

        @logger.debug("AwsFederatedCredentials#fresh_credentials") { "returning creds; new expiry #{@expires_at}" }

        Aws::Credentials.new(res.credentials.access_key_id, res.credentials.secret_access_key, res.credentials.session_token)
      end

      def expired?
        @logger.debug("AwsFederatedCredentials#expired?") { "Expiry check; @expires_at=#{@expires_at.inspect}" }
        @expires_at.nil? || (Time.now.utc + EXPIRY_GRACE_PERIOD_SECONDS > @expires_at)
      end

      private

      def sts_client
        @sts_client ||= Aws::STS::Client.new(region: @region)
      end
    end
  end
end
