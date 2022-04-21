require "aws-sdk-kms"
require "bson"
require "cbor"
require "grpc"
require "openssl"
require "securerandom"

require "cipherstash/collection"
require "cipherstash/grpc"
require "cipherstash/index"
require "cipherstash/record"

require_relative "./cryptinator"

# Just treat dates like times for CBOR 'cos YOLO
class Date
  def to_cbor(*args)
    self.to_time.to_cbor(*args)
  end
end

module CipherStash
  class Client
    # Class that wraps all the gRPC endpoints we support.
    #
    # Does all the input validation/encryption/serialisation, and response
    # deserialisation/decryption/validation.  Method names mirror the RPC
    # names, however arguments and return types are the types exposed to users,
    # because nobody wants to write an extra layer of translation.
    #
    # Only intended for use within CipherStash::Client.
    #
    # @private
    #
    class RPC
      include Stash::GRPC::V1

      def initialize(profile, logger)
        @profile, @logger = profile, logger

        @logger.debug("CipherStash::Client::RPC") { "Connecting to data-service at '#{@profile.service_host}:#{@profile.service_port}'" }
      end

      def collection_info(name)
        res = stub.collection_info(Collections::InfoRequest.new(ref: ref(name)), metadata: rpc_headers)
        unless res.is_a?(Collections::InfoReply)
          raise Error::CollectionInfoFailure, "expected Collections::InfoReply response, got #{res.class} instead"
        end

        decrypt_collection_info(res)
      end

      def collection_list
        res = stub.collection_list(Collections::ListRequest.new, metadata: rpc_headers)
        unless res.is_a?(Collections::ListReply)
          raise Error::CollectionListFailure, "expected Collections::ListReply response, got #{res.class} instead"
        end

        res.collections.map { |c| decrypt_collection_info(c) }
      end

      def delete_collection(collection)
        res = stub.delete_collection(Collections::DeleteRequest.new(ref: collection.ref), metadata: rpc_headers)
        unless res.is_a?(Collections::InfoReply)
          raise Error::CollectionDeleteFailure, "expected Collections::InfoReply response, got #{res.class} instead"
        end

        true
      end

      def put(collection, id, record, vectors)
        res = stub.put(
          Documents::PutRequest.new(
            collectionId: blob_from_uuid(collection.id),
            source: { id: blob_from_uuid(id), source: record.nil? ? "" : encrypt_blob(record.to_cbor) },
            vectors: vectors
          ),
          metadata: rpc_headers
        )

        unless res.is_a?(Documents::PutReply)
          raise Error::RecordPutFailure, "expected Documents::PutReply response, got #{res.class} instead"
        end

        uuid_from_blob(id)
      end

      def get(collection, id)
        res = stub.get(Documents::GetRequest.new(collectionId: blob_from_uuid(collection.id), id: blob_from_uuid(id)), metadata: rpc_headers)
        unless res.is_a?(Documents::GetReply)
          raise Error::RecordGetFailure, "expected Documents::GetReply response, got #{res.class} instead"
        end

        decrypt_record(res.source)
      end

      def get_all(collection, ids)
        res = stub.get_all(Documents::GetAllRequest.new(collectionId: blob_from_uuid(collection.id), ids: ids.map { |x| blob_from_uuid(x) }), metadata: rpc_headers)
        unless res.is_a?(Documents::GetAllReply)
          raise Error::RecordGetFailure, "expected Documents::GetAllReply response, got #{res.class} instead"
        end

        res.documents.map { |r| decrypt_record(r) }
      end

      def delete(collection, id)
        res = stub.delete(Documents::DeleteRequest.new(collectionId: blob_from_uuid(collection.id), id: blob_from_uuid(id)), metadata: rpc_headers)
        unless res.is_a?(Documents::DeleteReply)
          raise Error::RecordDeleteFailure, "expected Documents::DeleteReply response, got #{res.class} instead"
        end

        true
      end

      def query(collection, q)
        res = stub.query(Queries::QueryRequest.new(collectionId: blob_from_uuid(collection.id), query: q), metadata: rpc_headers)

        unless res.is_a?(Queries::QueryReply)
          raise Error::RecordDeleteFailure, "expected Queries::QueryReply response, got #{res.class} instead"
        end

        Struct.new(:records, :aggregates).new(res.records.map { |r| decrypt_record(r) }, res.aggregates)
      end

      private

      def stub
        @stub ||= begin
                    creds = if ts = @profile.service_trust_anchor
                              ::GRPC::Core::ChannelCredentials.new(ts)
                            else
                              ::GRPC::Core::ChannelCredentials.new
                            end

                    CipherStash::GRPC::Stub.new("#{@profile.service_host}:#{@profile.service_port}", creds)
                  end
      end

      def rpc_headers
        { authorization: "Bearer #{@profile.data_service_credentials[:access_token]}" }
      end

      def decrypt_collection_info(info)
        unless info.is_a?(Collections::InfoReply)
          raise Error::DecryptionFailure, "expected Collections::InfoReply, got #{info.class} instead"
        end

        Collection.new(
          self,
          uuid_from_blob(info.id),
          info.ref,
          metadata = unbson(Cryptinator.new(@profile, @logger).decrypt(info.metadata)),
          info.indexes.map { |i| decrypt_index(i) }
        )
      end

      def decrypt_index(idx)
        unless idx.is_a?(Indexes::Index)
          raise Error::DecryptionFailure, "expected Indexes::Index, got #{idx.class} instead"
        end

        Index.new(
          uuid_from_blob(idx.id),
          unbson(Cryptinator.new(@profile, @logger).decrypt(idx.settings))
        )
      end

      def decrypt_record(r)
        unless r.is_a?(Documents::Document)
          raise Error::DecryptionFailure, "expected Documents::Document, got #{r.class} instead"
        end

        Record.new(
          uuid_from_blob(r.id),
          r.source == "" ? nil : CBOR.unpack(Cryptinator.new(@profile, @logger).decrypt(r.source))
        )
      end

      def uuid_from_blob(blob)
        blob.unpack("H*").first.scan(/^(.{8})(.{4})(.{4})(.{4})(.*)$/).join("-")
      end

      def blob_from_uuid(uuid)
        [uuid.gsub("-", "")].pack("H*")
      end

      def encrypt_blob(blob)
        Cryptinator.new(@profile, @logger).encrypt(blob)
      end

      def unbson(s)
        Hash.from_bson(BSON::ByteBuffer.new(s))
      end

      def ref(name)
        OpenSSL::HMAC.digest(OpenSSL::Digest::SHA256.new, naming_key, name)
      end

      def naming_key
        @naming_key ||= begin
                          Aws::KMS::Client.new(@profile.kms_credentials).decrypt(ciphertext_blob: @profile.naming_key).plaintext
                        end
      end
    end

    private_constant :RPC
  end
end
