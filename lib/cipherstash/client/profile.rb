require "aws-sdk-core/credentials"
require "deep_merge"
require "json"

require_relative "./error"
require_relative "./data_service_credentials_manager"

module CipherStash
  class Client
    # Aaaaaaaaall the configuration for the client.
    #
    # @private
    class Profile
      def self.load(maybe_name, logger)
        maybe_profile_name = resolve_profile_name(maybe_name)
        profile_name = maybe_profile_name || "default"

        profile_data = begin
          logger.debug("CipherStash::Profile.load") { "Reading data for profile '#{profile_name}' from ~/.cipherstash/#{profile_name}/profile-config.json" }
          profile_data = JSON.parse(File.read(file_path(profile_name, "profile-config.json")))

        rescue Errno::ENOENT
          if maybe_profile_name.nil?
            {}
          else
            raise Error::LoadProfileFailure, "Profile '#{profile_name}' does not exist"
          end
        rescue JSON::ParserError => ex
          raise Error::LoadProfileFailure, "Profile '#{profile_name}' has an invalid profile-config.json: #{ex.message}"
        end.deep_merge(default_profile)

        profile_data = override_via_environment(profile_data, logger)

        Profile.new(profile_name, profile_data, logger)
      end

      class << self
        private

        # Figure out what profile name we're supposed to be loading.
        # If the user has not specified a preference, we return `nil`, because
        # we need to be able to differentiate between "user asked for the profile
        # named 'default'" and "user did not ask for a profile name".
        def resolve_profile_name(name)
          # Passed in as the constructor has the highest precedence, so
          # maybe we can get this over and done with quickly?
          unless name.nil?
            return name
          end

          # Specified-by-env-var gets next priority
          unless (name = ENV["CS_PROFILE_NAME"]).nil?
            return name
          end

          # Maybe they wrote it down?
          begin
            cfg = JSON.parse(File.read(File.expand_path("~/.cipherstash/config.json")))

            unless (name = cfg["defaultProfile"]).nil?
              return name
            end
          rescue Errno::ENOENT
            # This Is Fine
          rescue JSON::ParserError => ex
            raise Error::LoadProfileFailure, "Could not parse ~/.cipherstash/config.json: #{ex.message}"
          rescue ex
            raise Error::LoadProfileFailure, "Error while reading ~/.cipherstash/config.json: #{ex.message} (#{ex.class})"
          end

          nil
        end

        def default_profile
          {
            "service" => {
              "host" => "ap-southeast-2.aws.stashdata.net",
              "port" => 443,
            },
            "identityProvider" => {
              "host"     => "https://auth.cipherstash.com/",
              "clientId" => "CtY9DNGongoSvZaAwbb6sw0Hr7Gl7pg7",
            },
          }
        end

        def override_via_environment(data, logger)
          # Strings
          {
            "CS_WORKSPACE"               => "service.workspace",
            "CS_SERVICE_FQDN"            => "service.host",
            "CS_SERVICE_TRUST_ANCHOR"    => "service.trustAnchor",
            "CS_IDP_HOST"                => "identityProvider.host",
            "CS_IDP_CLIENT_ID"           => "identityProvider.clientId",
            "CS_IDP_CLIENT_SECRET"       => "identityProvider.clientSecret",
            "CS_ACCESS_TOKEN"            => "identityProvider.accessToken",
            "CS_KMS_KEY_ARN"             => "keyManagement.key.arn",
            "CS_KMS_KEY_REGION"          => "keyManagement.key.region",
            "CS_NAMING_KEY"              => "keyManagement.key.namingKey",
            "CS_KMS_FEDERATION_ROLE_ARN" => "keyManagement.awsCredentials.roleArn",
            "CS_AWS_ACCESS_KEY_ID"       => "keyManagement.awsCredentials.accessKeyId",
            "CS_AWS_SECRET_ACCESS_KEY"   => "keyManagement.awsCredentials.secretAccessKey",
            "CS_AWS_REGION"              => "keyManagement.awsCredentials.region",
          }.each do |var, path|
            if ENV.key?(var)
              logger.debug("CipherStash::Profile.load") { "Overriding profile value of #{path} with value from #{var}: #{ENV[var].inspect}" }
              nested_set(data, path, ENV[var])
            end
          end

          # Numberz
          {
            "CS_SERVICE_PORT" => "service.port",
          }.each do |var, path|
            if ENV.key?(var)
              logger.debug("CipherStash::Profile.load") { "Overriding profile value of #{path} with value from #{var}: #{ENV[var].inspect}" }
              nested_set(data, path, ENV[var].to_i)
            end
          end

          data
        end

        def nested_set(h, k, v)
          f, r = k.split(".", 2)
          if r.nil?
            h[k] = v
          else
            h[f] ||= {}
            h[f] = nested_set(h[f], r, v)
          end
          h
        end

        def file_path(p, f)
          File.expand_path(File.join("~/.cipherstash/#{p}", f))
        end
      end

      # Constructor for a profile.
      #
      # Typically you will want to use Profile.load() instead of this method,
      # as that takes care of file I/O and incorporating data from other
      # sources, such as the environment.
      def initialize(name, data, logger)
        @name, @data, @logger = name, data, logger
      end

      # The name of the profile.
      attr_reader :name

      # The defined service host for this profile.
      def service_host
        @data["service"]["host"]
      end

      # The defined service port for this profile.
      def service_port
        @data["service"]["port"]
      end

      # The list of trust anchors for this profile.
      def service_trust_anchor
        @data["service"]["trustAnchor"]
      end

      # A raw dump of the IdP config from the profile.
      #
      def identity_provider_config
        @data["identityProvider"]
      end

      # The credentials needed to access the data-service.
      #
      # Call this method every time you need creds, don't cache the return value yourself.
      # Credentials are usually short-lived, and need periodic refreshing.  This method
      # handles detecting when credentials need refreshing and handles that behind the
      # scenes.
      #
      # @return [Hash<access_token: String>]
      def data_service_credentials
        @data_service_credentials ||= DataServiceCredentialsManager.new(self, @logger)

        @data_service_credentials.fresh_credentials
      end

      # A set of credentials suitable for accessing the KMS key for this profile.
      #
      # Call this method every time you need creds, don't cache the return value yourself.
      # Credentials are usually short-lived, and need periodic refreshing.  This method
      # handles detecting when credentials need refreshing and handles that behind the
      # scenes.
      #
      # The returned hash is suitable for passing to KMS::Client as
      # `KMS::Client.new(**profile.kms_credentials)`.
      def kms_credentials
        region = kms_key_arn.split(":")[3]

        {
          region: region,
          credentials: case @data["keyManagement"]["awsCredentials"]["kind"]
                       when "Federated"
                         aws_federated_credentials
                       when "Explicit"
                         aws_explicit_credentials
                       else
                         raise "Unexpected AWS credentials kind #{@data["keyManagement"]["awsCredentials"]["kind"]}"
                       end
        }
      end

      # The KMS key ARN for this profile.
      def kms_key_arn
        @data["keyManagement"]["key"]["arn"]
      end

      # The (encrypted) naming key for this profile.
      def naming_key
        @data["keyManagement"]["key"]["namingKey"].unpack("m").first
      end

      # Rummage up the cached token for this profile.
      #
      # If the token can't be read, returns a null token, because you're supposed to
      # refresh the token if it's out-of-date anyway.
      def read_cached_token
        JSON.parse(File.read(file_path("auth-token.json")))
      rescue
        { "accessToken": "", "refreshToken": "", expiry: 0 }
      end

      private

      def aws_federated_credentials
        @federated_credentials ||= begin
                                     Aws::AssumeRoleWebIdentityCredentials.new(
                                       role_arn: @data["keyManagement"]["awsCredentials"]["roleArn"],
                                       role_session_name: "StashRB",
                                       web_identity_token_file: file_path("auth-token.jwt"),
                                       client: Aws::STS::Client.new,
                                       before_refresh: ->(_) {
                                         File.write(file_path("auth-token.jwt"), data_service_credentials[:access_token], perm: 0600)
                                       }
                                     )
                                   end

        @federated_credentials.credentials
      end

      def aws_explicit_credentials
        Aws::Credentials.new(
          @data["keyManagement"]["awsCredentials"]["accessKeyId"],
          @data["keyManagement"]["awsCredentials"]["secretAccessKey"],
          @data["keyManagement"]["awsCredentials"]["sessionToken"]
        )
      end

      def file_path(f)
        File.expand_path(File.join("~/.cipherstash/#{@name}", f))
      end
    end
  end
end
