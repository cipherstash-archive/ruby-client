require "aws-sdk-core"
require "json"
require "net/http"
require "securerandom"

require_relative "./error"
require_relative "./auth0_device_code_credentials"
require_relative "./aws_federated_credentials"
require_relative "./console_access_key_credentials"
require_relative "./console"
require_relative "./creds_proxy"
require_relative "./hash_helper"

module CipherStash
  class Client
    # Aaaaaaaaall the configuration for the client.
    #
    # @private
    class Profile
      include HashHelper

      ENV_OPT_MAPPING = {
        "CS_PROFILE_NAME"            => :profileName,
        "CS_WORKSPACE"               => :workspace,
        "CS_SERVICE_FQDN"            => :serviceFqdn,
        "CS_SERVICE_PORT"            => :servicePort,
        "CS_SERVICE_TRUST_ANCHOR"    => :serviceTrustAnchor,
        "CS_IDP_HOST"                => :idpHost,
        "CS_IDP_CLIENT_ID"           => :idpClientId,
        "CS_IDP_CLIENT_SECRET"       => :idpClientSecret,
        "CS_ACCESS_TOKEN"            => :accessToken,
        "CS_KMS_KEY_ARN"             => :kmsKeyArn,
        "CS_KMS_KEY_REGION"          => :kmsKeyRegion,
        "CS_LOCAL_KEY"               => :localKey,
        "CS_NAMING_KEY"              => :namingKey,
        "CS_KMS_FEDERATION_ROLE_ARN" => :kmsFederationRoleArn,
        "CS_AWS_ACCESS_KEY_ID"       => :awsAccessKeyId,
        "CS_AWS_SECRET_ACCESS_KEY"   => :awsSecretAccessKey,
        "CS_AWS_REGION"              => :awsRegion,
      }

      OPT_ENV_MAPPING = ENV_OPT_MAPPING.invert

      private_constant :ENV_OPT_MAPPING, :OPT_ENV_MAPPING

      def self.profile_options
        @profile_options ||= OPT_ENV_MAPPING.keys.freeze
      end

      def self.load(maybe_name, logger, **opts)
        maybe_profile_name = resolve_profile_name(maybe_name)
        profile_name = maybe_profile_name || "default"

        profile_data = begin
          if ENV["CS_SKIP_PROFILE_LOAD"]
            default_profile
          else
            logger.debug("CipherStash::Profile.load") { "Reading data for profile '#{profile_name}' from ~/.cipherstash/#{profile_name}/profile-config.json" }
            profile_data = JSON.parse(File.read(file_path(profile_name, "profile-config.json")))
          end
        rescue Errno::ENOENT
          if maybe_profile_name.nil?
            logger.debug("CipherStash::Profile.load") { "~/.cipherstash/default/profile-config.json does not exist; going with built-in defaults" }
            default_profile
          else
            raise Error::LoadProfileFailure, "Profile '#{profile_name}' does not exist"
          end
        rescue JSON::ParserError => ex
          raise Error::LoadProfileFailure, "Profile '#{profile_name}' has an invalid profile-config.json: #{ex.message}"
        end

        profile_data = override_via_options(override_via_environment(profile_data, logger), opts, logger)

        Profile.new(profile_name, profile_data, logger)
      end

      def self.create(name, logger, **opts)
        begin
          Dir.mkdir(File.expand_path("~/.cipherstash"))
          logger.debug("CipherStash::Client::Profile.create") { "Created ~/.cipherstash" }
        rescue Errno::EEXIST
          # This Is Fine (sip)
          logger.debug("CipherStash::Client::Profile.create") { "~/.cipherstash already exists" }
        rescue => ex
          raise Error::CreateProfileFailure, "Could not create ~/.cipherstash: #{ex.message} (#{ex.class})"
        end

        begin
          Dir.mkdir(File.expand_path("~/.cipherstash/#{name}"))
          logger.debug("CipherStash::Client::Profile.create") { "Created ~/.cipherstash/#{name}" }
        rescue Errno::EEXIST
          if name == "default"
            incoming_workspace_id = opts[:workspace]

            profile_config = File.read(File.expand_path("~/.cipherstash/#{name}/profile-config.json"))
            parsed_profile_config = JSON.parse(profile_config)

            default_profile_workspace_id = parsed_profile_config["service"]["workspace"]

            if incoming_workspace_id == default_profile_workspace_id
              raise Error::CreateProfileFailure, "Could not create profile #{name.inspect}: already exists"
            else
              logger.debug("CipherStash::Client::Profile.create") { "~/.cipherstash/#{name} created with Workspace ID: #{default_profile_workspace_id}. Updating #{name} profile to use Workspace ID: #{incoming_workspace_id}." }
            end
          else
            raise Error::CreateProfileFailure, "Could not create profile #{name.inspect}: already exists"
          end

        rescue => ex
          raise Error::CreateProfileFailure, "Could not create profile directory ~/.cipherstash/#{name}: #{ex.message} (#{ex.class})"
        end

        begin
          if name == "default" && File.exists?(File.expand_path("~/.cipherstash/#{name}/auth-token.json"))
            File.delete(File.expand_path("~/.cipherstash/#{name}/auth-token.json"))
          end

          File.write(File.expand_path("~/.cipherstash/#{name}/profile-config.json"), default_profile.to_json)
          logger.debug("CipherStash::Client::Profile.create") { "Wrote ~/.cipherstash/#{name}/profile-config.json" }
        rescue => ex
          raise Error::CreateProfileFailure, "Could not write ~/.cipherstash/#{name}/profile-config.json: #{ex.message} (#{ex.class})"
        end

        profile = Profile.load(name, logger, **opts)
        profile.refresh_from_console
        profile.save
      end

      def self.login(workspace:, profile_name:, logger:)
        is_initial_login = !workspace.nil?
        profile_name = resolve_profile_name(profile_name) || "default"

        if is_initial_login
          create(profile_name, logger, workspace: workspace)
        else
          load(profile_name, logger).login
        end
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
              "kind"     => "Auth0-DeviceCode",
              "host"     => "auth.cipherstash.com",
              "clientId" => "CtY9DNGongoSvZaAwbb6sw0Hr7Gl7pg7",
            },
          }
        end

        def override_via_options(data, opts, logger)
          override_profile(data, opts, logger, ->(n) { n })
        end

        def override_via_environment(data, logger)
          opts = ENV_OPT_MAPPING.each.with_object({}) { |(k, v), o| o[v] = ENV[k] if ENV.key?(k) }

          override_profile(data, opts, logger, ->(n) { OPT_ENV_MAPPING[n] })
        end

        def override_profile(data, opts, logger, name_xlat)
          if opts[:accessToken]
            %i{idpClientId idpClientSecret}.each do |k|
              if opts.key?(k)
                raise Error::InvalidProfileError, "Cannot set both #{name_xlat.call(k)} and #{name_xlat.call(:accessToken)}"
              end
            end

            logger.debug("CipherStash::Profile.override_profile") { "Setting identityProvider.kind to Auth0-AccessToken because #{name_xlat.call(:accessToken)} is set" }

            data["identityProvider"] = {
              "kind" => "Auth0-AccessToken",
              "accessToken" => opts[:accessToken],
            }
          else
            data["identityProvider"] ||= {}
            if opts.key?(:idpClientSecret) && opts.key?(:idpClientId)
              logger.debug("CipherStash::Profile.override_profile") { "Setting identityProvider.kind to Auth0-Machine2Machine because #{name_xlat.call(:idpClientSecret)} and #{name_xlat.call(:idpClientId)} are both set" }
              data["identityProvider"] = {
                "kind" => "Auth0-Machine2Machine",
                "host" => "auth.cipherstash.com",
                "clientId" => opts[:idpClientId],
                "clientSecret" => opts[:idpClientSecret],
              }
            elsif opts.key?(:idpClientId)
              logger.debug("CipherStash::Profile.override_profile") { "Setting identityProvider.kind to Auth0-DeviceCode because #{name_xlat.call(:idpClientId)} is set" }
              data["identityProvider"] = {
                "kind" => "Auth0-DeviceCode",
                "host" => "auth.cipherstash.com",
                "clientId" => opts[:idpClientId],
              }
            elsif opts.key?(:idpClientSecret)
              logger.debug("CipherStash::Profile.override_profile") { "Setting identityProvider.kind to Console-AccessKey because #{name_xlat.call(:idpClientSecret)} is set" }
              data["identityProvider"] = {
                "kind" => "Console-AccessKey",
                "host" => "console.cipherstash.com",
                "clientSecret" => opts[:idpClientSecret],
              }
            end
          end

          if opts.key?(:localKey)
            %i{kmsKeyArn kmsKeyRegion kmsFederationRoleArn awsAccessKeyId awsSecretAccessKey awsSessionToken awsRegion}.each do |k|
              if opts.key?(k)
                raise Error::InvalidProfileError, "Cannot set both #{name_xlat.call(k)} and #{name_xlat.call(:localKey)}"
              end
            end

            logger.debug("CipherStash::Profile.override_profile") { "Setting keyManagement.kind to Static because #{name_xlat.call(:localKey)} is set" }
            data["keyManagement"] ||= {}
            data["keyManagement"]["kind"] = "Static"
            data["keyManagement"]["key"] ||= {}
            data["keyManagement"]["key"]["key"] = opts[:localKey]
            data["keyManagement"].delete("awsCredentials")
          elsif opts.key?(:kmsKeyArn)
            logger.debug("CipherStash::Profile.override_profile") { "Setting keyManagment.kind to AWS-KMS because #{name_xlat.call(:kmsKeyArn)} is set" }
            data["keyManagement"] ||= {}
            data["keyManagement"]["kind"] = "AWS-KMS"
            data["keyManagement"]["key"] ||= {}
            data["keyManagement"]["key"]["arn"] = opts[:kmsKeyArn]

            unless data["keyManagement"].key?("awsCredentials")
              logger.debug("CipherStash::Profile.override_profile") { "Configuring federated keyManagement.awsCredentials based on #{name_xlat.call(:kmsKeyArn)}" }
              keybits = opts[:kmsKeyArn].split(":")

              data["keyManagement"]["awsCredentials"] = {
                "kind"    => "Federated",
                "region"  => keybits[3],
                "roleArn" => "arn:aws:iam::#{keybits[4]}:role/cs-federated-cmk-access",
              }.tap { |v| logger.debug("CipherStash::Profile.override_profile") { "Default keyManagement.awsCredentials: #{v.inspect}" } }
            end
          end

          if opts.key?(:kmsFederationRoleArn)
            data["keyManagement"] ||= {}
            data["keyManagement"]["awsCredentials"] ||= {}
            %i{awsAccessKeyId awsSecretAccessKey awsSessionToken}.each do |k|
              if opts.key?(k)
                raise Error::InvalidProfileError, "Cannot set both #{name_xlat.call(k)} and #{name_xlat.call(:kmsFederationRoleArn)}"
              end
            end

            logger.debug("CipherStash::Profile.override_profile") { "Setting keyManagement.awsCredentials.kind to Federated because #{name_xlat.call(:kmsFederationRoleArn)} is set" }

            data["keyManagement"]["awsCredentials"]["kind"] = "Federated"
            data["keyManagement"]["awsCredentials"]["roleArn"] = opts[:kmsFederationRoleArn]
          elsif opts.key?(:awsAccessKeyId)
            data["keyManagement"] ||= {}
            data["keyManagement"]["awsCredentials"] ||= {}
            unless opts.key?(:awsSecretAccessKey)
              raise Error::InvalidProfileError, "Must set #{name_xlat.call(:awsSecretAccessKey)} when setting #{name_xlat.call(:awsAccessKeyId)}"
            end

            logger.debug("CipherStash::Profile.override_profile") { "Setting keyManagement.awsCredentials.kind to Explicit because #{name_xlat.call(:awsAccessKeyId)} is set" }

            data["keyManagement"]["awsCredentials"]["kind"] = "Explicit"
            data["keyManagement"]["awsCredentials"]["accessKeyId"] = opts[:awsAccessKeyId]
            data["keyManagement"]["awsCredentials"]["secretAccessKey"] = opts[:awsSecretAccessKey]
            data["keyManagement"]["awsCredentials"]["sessionToken"] = opts[:awsSessionToken] if opts.key?(:awsSessionToken)
          else
            %i{awsSecretAccessKey awsSessionToken}.each do |k|
              if opts.key?(k)
                raise Error::InvalidProfileError, "Cannot set #{name_xlat.call(k)} unless #{name_xlat.call(:awsAccessKeyId)} is set"
              end
            end
          end

          # String values that are just leaf values and have no impact on other
          # values within the profile
          {
            :workspace          => "service.workspace",
            :serviceFqdn        => "service.host",
            :serviceTrustAnchor => "service.trustAnchor",
            :idpHost            => "identityProvider.host",
            :kmsKeyRegion       => "keyManagement.key.region",
            :namingKey          => "keyManagement.key.namingKey",
            :awsRegion          => "keyManagement.awsCredentials.region",
          }.each do |var, path|
            if opts.key?(var)
              logger.debug("CipherStash::Profile.override_profile") { "Setting #{path} to #{opts[var].inspect} from #{name_xlat.call(var)}" }
              nested_set(data, path, opts[var])
            end
          end

          # Numberz
          {
            :servicePort => "service.port",
          }.each do |var, path|
            if opts.key?(var)
              logger.debug("CipherStash::Profile.override_profile") { "Setting #{path} to #{opts[var].inspect} from #{name_xlat.call(var)}" }
              nested_set(data, path, opts[var].to_i)
            end
          end

          data
        end

        def nested_set(h, k, v)
          f, r = k.split(".", 2)
          if r.nil?
            if v.nil?
              h.delete(k)
            else
              h[k] = v
            end
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

        @logger.debug("CipherStash::Client::Profile.new") { "Creating profile named #{name.inspect} from #{data.inspect}" }
      end

      # The name of the profile.
      attr_reader :name

      # The defined service workspace for this profile.
      def workspace
        @data["service"]["workspace"]
      end

      # The defined service host for this profile.
      def service_host
        @data["service"]["host"]
      end

      # The defined service port for this profile.
      def service_port
        @data["service"]["port"] || 443
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

      # Generate an arbitrary object using a fresh CipherStash access token.
      #
      # The block passed to this method will be called whenever the access
      # token expires, so that an expensive object creation doesn't have to
      # be repeated on every call.
      #
      # @see #with_kms_credentials because it has a more in-depth explanation of what's going on and why.
      #
      def with_access_token(&blk)
        @access_token_creds_provider ||= access_token_provider(**symbolize_keys(identity_provider_config))

        if blk.nil?
          @access_token_creds_provider.fresh_credentials
        else
          CredsProxy.new(@access_token_creds_provider) do
            blk.call(@access_token_creds_provider.fresh_credentials)
          end
        end
      end

      # Generate an arbitrary object using a fresh set of KMS credentials.
      #
      # This is... complicated to explain, though easy to use.  Let's work from
      # examples.
      #
      # You want to do encryption and decryption with KMS.
      # In order to do that, you need to have credentials which you can pass
      # to your KMS client  Sensible people don't just hand out static IAM
      # access keys, they use AssumeRole (and friends), which provide short-lived
      # credentials.  So far, so good.
      #
      # Except... your KMS client might be used for a long time.  You don't want
      # to create a new instance of KMS::Client for every operation, because that's
      # going to (a) churn your GC, and (b) lose the advantages of pipelining, etc.
      # On the other hand, if you create a long-lived `KMS::Client` with temporary
      # credentials, eventually those credentials will expire and your KMS client
      # will stop working.
      #
      # Enter: `#with_kms_credentials`.  This function takes a block which is called
      # whenever new KMS credentials are needed, *and only then*.  The idea is that
      # the block you pass takes the credentials and instantiates some object, and
      # then `#with_kms_credentials` will cache that object until the credentials
      # need to be rotated.
      #
      def with_kms_credentials(&blk)
        @kms_creds_provider ||= aws_credentials_provider(**symbolize_keys(@data["keyManagement"]["awsCredentials"]))

        region = kms_key_arn.split(":")[3]
        CredsProxy.new(@kms_creds_provider) do
          blk.call({ region: region, credentials: @kms_creds_provider.credentials })
        end
      end

      def using_kms_federation?
        @data["keyManagement"]["awsCredentials"]["kind"] rescue nil == "Federated"
      end

      def cipher_engine
        case @data["keyManagement"]["kind"]
        when "AWS-KMS"
          with_kms_credentials do |creds|
            Enveloperb::AWSKMS.new(
              kms_key_arn,
              aws_access_key_id: creds[:credentials].access_key_id,
              aws_secret_access_key: creds[:credentials].secret_access_key,
              aws_session_token: creds[:credentials].session_token,
              aws_region: creds[:region]
            )
          end
        when "Static"
          Enveloperb::Simple.new([@data["keyManagement"]["key"]["key"]].pack("H*"))
        else
          raise Error::InvalidProfileError, "Unrecognised value for keyManagement.kind: #{@data["keyManagement"]["kind"].inspect}"
        end
      end

      # The KMS key ARN for this profile.
      def kms_key_arn
        @data["keyManagement"]["key"]["arn"]
      end

      def ref_for(name)
        OpenSSL::HMAC.digest(OpenSSL::Digest::SHA256.new, naming_key, name)
      end

      # Write a new token to the cache
      def cache_access_token(t)
        File.write(file_path("auth-token.json"), t.to_json)
      end

      # Contact the CipherStash Console and retrieve core profile parameters,
      # then store them in the profile.
      def refresh_from_console
        if workspace.nil?
          raise Error::InvalidProfileError, "No workspace set"
        end

        @logger.debug("CipherStash::Client::Profile#refresh_from_console") { "Fetching KMS/naming key details for workspace #{workspace}" }
        details = Console.new(access_token: with_access_token[:access_token], logger: @logger).workspace_info(workspace)

        @data["keyManagement"] ||= { "kind" => "AWS-KMS" }
        @data["keyManagement"]["key"] ||= {}
        @data["keyManagement"]["key"]["arn"] ||= details["keyId"]
        @data["keyManagement"]["key"]["namingKey"] ||= details["namingKey"]
        @data["keyManagement"]["key"]["region"] ||= details["keyRegion"]

        if details["keyRoleArn"]
          @data["keyManagement"]["awsCredentials"] ||= {
            "kind" => "Federated",
            "roleArn" => details["keyRoleArn"],
            "region" => details["keyRegion"]
          }
        end
      end

      def save
        begin
          File.write(file_path("profile-config.json"), @data.to_json)
          @logger.debug("CipherStash::Client::Profile#save") { "Saved ~/.cipherstash/#{@name}/profile-config.json" }
        rescue => ex
          raise Error::SaveProfileFailure, "Failed to save to ~/.cipherstash/#{@name}/profile-config.json: #{ex.message} (#{ex.class})"
        end
      end

      # Create a new (encrypted) naming key from the profile's wrapping key.
      #
      # This method is not intended for regular use; typically, a single naming
      # key is generated when the workspace is first initialized, and then is
      # not changed thereafter.
      def generate_naming_key
        case @data["keyManagement"]["kind"]
        when "AWS-KMS"
          [with_kms_credentials do |creds|
            Aws::KMS::Client.new(**creds)
          end.generate_data_key(
            number_of_bytes: 32,
            key_id: kms_key_arn
          ).ciphertext_blob].pack("m0")
        when "Static"
          [cipher_engine.encrypt(SecureRandom.bytes(32)).to_s].pack("m0")
        else
          raise Error::InvalidProfileError, "Unrecognised value for keyManagement.kind: #{@data["keyManagement"]["kind"].inspect}"
        end
      end

      def login
        access_token_creds_provider = access_token_provider(**symbolize_keys(identity_provider_config))
        access_token_creds_provider.fresh_credentials

        self
      end

      private

      def access_token_provider(kind:, **opts)
        begin
          case kind
          when "Auth0-AccessToken"
            access_token_static_credentials(**opts)
          when "Auth0-DeviceCode"
            access_token_device_code_credentials(**opts)
          when "Console-AccessKey"
            access_token_console_access_key_credentials(**opts)
          else
            raise Error::InvalidProfileError, "Unknown identityProvider kind: #{kind}"
          end
        rescue ArgumentError => ex
          raise Error::InvalidProfileError, "Invalid identityProvider configuration #{opts.inspect}: #{ex.message}"
        end
      end

      def access_token_static_credentials(accessToken:)
        @logger.debug("CipherStash::Profile") { "Using static access token" }
        Struct.new(:fresh_credentials, :expired?).new({ access_token: accessToken }, false)
      end

      # Rummage up the cached token for this profile.
      #
      # If the token can't be read for any reason, just return a null token, because you're supposed to refresh the token if it's out-of-date anyway.
      def cached_token
        JSON.parse(File.read(file_path("auth-token.json")))
      rescue
        { "accessToken": "", "refreshToken": "", expiry: 0 }
      end

      def access_token_device_code_credentials(host:, clientId:)
        @logger.debug("CipherStash::Profile") { "Using device code authentication" }
        Auth0DeviceCodeCredentials.new(self, cached_token, @logger)
      end

      def access_token_console_access_key_credentials(host:, clientSecret:)
        @logger.debug("CipherStash::Profile") { "Using console access key authentication" }
        ConsoleAccessKeyCredentials.new(self, clientSecret, @logger)
      end

      def aws_credentials_provider(kind:, **opts)
        begin
          case kind
          when "Explicit"
            aws_explicit_credentials(**opts)
          when "Federated"
            aws_federated_credentials(**opts)
          else
            raise Error::InvalidProfileError, "Unknown KMS credentials kind: #{kind}"
          end
        rescue ArgumentError => ex
          raise Error::InvalidProfileError, "Invalid KMS credentials configuration: #{ex.message}"
        end
      end

      def aws_federated_credentials(roleArn:, region:)
        @logger.debug("CipherStash::Profile") { "Federating to #{@data["keyManagement"]["awsCredentials"]["roleArn"].inspect} for AWS credentials" }
        AwsFederatedCredentials.new(self, roleArn, region, @logger)
      end

      def aws_explicit_credentials(accessKeyId:, secretAccessKey:, sessionToken: nil, region:)
        Aws::Credentials.new(accessKeyId, secretAccessKey, sessionToken).tap do |creds|
          class << creds
            def expired?
              false
            end
          end
        end
      end

      def file_path(f)
        File.expand_path(File.join("~/.cipherstash/#{@name}", f))
      end

      # The plaintext naming key for this profile.
      def naming_key
        @naming_key ||= begin
                          case @data["keyManagement"]["kind"]
                          when "AWS-KMS"
                            encrypted_naming_key = @data["keyManagement"]["key"]["namingKey"].unpack("m").first
                            with_kms_credentials do |creds|
                              Aws::KMS::Client.new(**creds)
                            end.decrypt(ciphertext_blob: encrypted_naming_key).plaintext
                          when "Static"
                            cipher_engine.decrypt(Enveloperb::EncryptedRecord.new(@data["keyManagement"]["key"]["namingKey"].unpack("m").first))
                          else
                            raise Error::InvalidProfileError, "Unrecognised value for keyManagement.kind: #{@data["keyManagement"]["kind"].inspect}"
                          end
                        end
      end
    end
  end
end
