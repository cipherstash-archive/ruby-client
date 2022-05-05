require "net/http"

module CipherStash
  class Client
    # Methods for interacting with the CipherStash Console API.
    #
    # @private
    class Console
      def initialize(host: "console.cipherstash.com", port: 443, access_token:, logger:)
        @host, @port, @access_token, @logger = host, port, access_token, logger
      end

      def workspace_info(workspace_id)
        res = make_request(Net::HTTP::Get.new("/api/meta/workspaces/#{workspace_id}"))

        if res.code != "200"
          @logger.debug("CipherStash::Client::Profile#refresh_from_console") { "Console response #{res.code}: #{res.body.inspect}" }
          raise Error::LoadProfileFailure, "Console responded to workspace refresh request with HTTP #{res.code}"
        end

        begin
          JSON.parse(res.body)
        rescue JSON::ParserError => ex
          raise Error::ConsoleAccessFailure, "Failed to parse response from console: #{ex.message}"
        end
      end

      private

      def make_request(req)
        req["Authorization"] = "Bearer #{@access_token}"

        console_connection do |http|
          http.request(req)
        end
      end

      def console_connection(&blk)
        @console_connection ||= Net::HTTP.start(@host, @port, use_ssl: true)

        begin
          blk.call(@console_connection)
        rescue SystemCallError => ex
          @logger.debug("CipherStash::Client::Console#console_connection") { "Connection to console returned error: #{ex.message} (#{ex.class})" }
          @logger.info("CipherStash::Client::Console#console_connection") { "Console connection interrupted... reconnecting" }
          @console_connection = nil
          sleep 0.5
          console_connection(&blk)
        end
      end
    end
  end
end
