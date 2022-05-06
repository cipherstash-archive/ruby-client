require "time"

module CipherStash
  # Represents a CipherStash access key.
  #
  # An access key is a long-term credential suitable for use by non-interactive applications to authenticate their use of a CipherStash workspace.
  #
  class AccessKey
    # The name given to the access key when it was created.
    #
    # @return [String]
    attr_reader :name

    # The globally-unique ID of the access key.
    #
    # @return [String]
    attr_reader :id

    # The ID of the workspace that the access key grants access to.
    #
    # @return [String]
    attr_reader :workspace_id

    # When the access key was created.
    #
    # @return [Time]
    attr_reader :created_at

    # When the access key was last exchanged for an access token.
    #
    # @return [Time, NilClass] can be `nil` if the access key has never been used.
    attr_reader :last_used_at

    # The complete secret access key.
    #
    # @note this method will only provide the access key for an object
    #   returned from CipherStash::Client#create_access_key.  Listing
    #   access keys does not provide the secret access key.
    #
    # @return [String]
    attr_reader :secret_key

    # @private
    def initialize(keyName:, keyId:, workspaceId:, createdAt:, lastUsedAt: nil, secretKey: nil, **_opts)
      @name, @id, @workspace_id, @created_at, @last_used_at, @secret_key = keyName, keyId, workspaceId, Time.parse(createdAt), lastUsedAt.nil? ? nil : Time.parse(lastUsedAt), secretKey
    end
  end
end
