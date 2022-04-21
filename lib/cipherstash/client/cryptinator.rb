require "open3"

require_relative "./error"

module CipherStash
  class Client
    # The dodgiest way to encrypt and decrypt things via the AWS Encryption API that could possibly work.
    #
    # @private
    class Cryptinator
      def initialize(profile, logger)
        @profile, @logger = profile, logger
      end

      def decrypt(c)
        Open3.popen2(creds_env, *command_line(:decrypt)) do |stdin, stdout, waiter|
          stdin.write(Base64.encode64(c))
          stdin.close
          status = waiter.value

          if status.exitstatus != 0
            raise Error::DecryptionFailure, "aws-encryption-cli failed with status #{status.exitstatus}"
          end

          Base64.decode64(stdout.read.force_encoding("BINARY"))
        end
      end

      def encrypt(p)
        Open3.popen2(creds_env, *command_line(:encrypt)) do |stdin, stdout, waiter|
          stdin.write(Base64.encode64(p))
          stdin.close
          status = waiter.value

          if status.exitstatus != 0
            raise Error::DecryptionFailure, "aws-encryption-cli failed with status #{status.exitstatus}"
          end

          Base64.decode64(stdout.read.force_encoding("BINARY"))
        end
      end

      private

      def creds_env
        creds = @profile.kms_credentials

        {
          "AWS_DEFAULT_REGION"    => creds[:region],
          "AWS_REGION"            => creds[:region],
          "AWS_ACCESS_KEY_ID"     => creds[:credentials].access_key_id,
          "AWS_SECRET_ACCESS_KEY" => creds[:credentials].secret_access_key,
          "AWS_SESSION_TOKEN"     => creds[:credentials].session_token,
          "AWS_SECURITY_TOKEN"    => creds[:credentials].session_token,
        }
      end

      def base_command
        [
          "aws-encryption-cli",
          "-i",
          "-",
          "-o",
          "-",
          "--suppress-metadata",
          "--decode",
          "--encode",
          "--wrapping-keys",
          "provider=aws-kms",
          "key=#{@profile.kms_key_arn}",
        ]
      end

      def command_line(mode)
        action_arg = case mode
                     when :encrypt
                       "--encrypt"
                     when :decrypt
                       "--decrypt"
                     else
                       raise Error::CryptinatorInternalFailure, "Unknown mode passed: #{mode.inspect}"
                     end

        (base_command + [action_arg]).tap do |cmd|
          @logger.debug("CipherStash::Client::Cryptinator") { "Running cryptinator command: #{cmd.inspect}" }
        end
      end
    end
  end
end
