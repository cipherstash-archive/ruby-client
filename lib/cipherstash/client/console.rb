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

      def create_access_key(name, workspace_id)
        req = Net::HTTP::Post.new("/api/access-key")
        req.body = { workspaceId: workspace_id, keyName: name }.to_json
        req["Content-Type"] = "application/json"
        res = make_request(req)

        if res.code != "200"
          @logger.debug("CipherStash::Client::Profile#create_access_key") { "Console response #{res.code}: #{res.body.inspect}" }
          raise Error::ConsoleAccessFailure, "Console responded to workspace access key creation request with HTTP #{res.code}"
        end

        k = res.body

        {
          "keyName" => name,
          "keyId" => k.split(".").first,
          "workspaceId" => workspace_id,
          "createdAt" => Time.now.utc.to_s,
          "secretKey" => k,
        }
      end

      def access_key_list(workspace_id)
        res = make_request(Net::HTTP::Get.new("/api/access-keys/#{workspace_id}"))

        if res.code != "200"
          @logger.debug("CipherStash::Client::Profile#access_key_list") { "Console response #{res.code}: #{res.body.inspect}" }
          raise Error::ConsoleAccessFailure, "Console responded to workspace access key list request with HTTP #{res.code}"
        end

        if res.body == ""
          []
        else
          begin
            JSON.parse(res.body)
          rescue JSON::ParserError => ex
            raise Error::ConsoleAccessFailure, "Failed to parse response from console: #{ex.message}"
          end
        end
      end

      def delete_access_key(name, workspace_id)
        req = Net::HTTP::Delete.new("/api/access-key")
        req.body = { workspaceId: workspace_id, keyName: name }.to_json
        req["Content-Type"] = "application/json"
        res = make_request(req)

        if res.code != "200"
          @logger.debug("CipherStash::Client::Profile#delete_access_key") { "Console response #{res.code}: #{res.body.inspect}" }
          raise Error::ConsoleAccessFailure, "Console responded to workspace access key deletion request with HTTP #{res.code}"
        end

        true
      end

      private

      def make_request(req, retries: 3)
        req["Authorization"] = "Bearer #{@access_token}"

        res = console_connection do |http|
          http.request(req)
        end

        if res.code =~ /^5/
          if retries > 0
            @logger.debug("CipherStash::Client::Profile#make_request") { "Retrying because console returned HTTP #{res.code}: #{res.body.inspect}" }
            make_request(req, retries: retries - 1)
          else
            @logger.debug("CipherStash::Client::Profile#make_request") { "Our of retries, final console response is HTTP #{res.code}: #{res.body.inspect}" }
            res
          end
        else
          res
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
