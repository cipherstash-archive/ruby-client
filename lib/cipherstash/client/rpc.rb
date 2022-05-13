require "aws-sdk-kms"
require "cbor"
require "enveloperb"
require "grpc"
require "openssl"
require "securerandom"

require "cipherstash/collection"
require "cipherstash/grpc"
require "cipherstash/index"
require "cipherstash/record"

require_relative "../collection/query_result"

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

        @cipher_engine = @profile.with_kms_credentials do |creds|
          Enveloperb::AWSKMS.new(
            @profile.kms_key_arn,
            aws_access_key_id: creds[:credentials].access_key_id,
            aws_secret_access_key: creds[:credentials].secret_access_key,
            aws_session_token: creds[:credentials].session_token,
            aws_region: creds[:region]
          )
        end
      end

      def collection_info(name)
        res = stub.collection_info(Collections::InfoRequest.new(ref: @profile.ref_for(name)), metadata: rpc_headers)
        unless res.is_a?(Collections::InfoReply)
          raise Error::CollectionInfoFailure, "expected Collections::InfoReply response, got #{res.class} instead"
        end

        decrypt_collection_info(res)
      rescue ::GRPC::NotFound
        raise Error::CollectionInfoFailure, "Collection '#{name}' not found"
      rescue ::GRPC::BadStatus => ex
        raise Error::CollectionInfoFailure, "Error while getting collection info for '#{name}': #{ex.message} (#{ex.class})"
      end

      def collection_list
        res = stub.collection_list(Collections::ListRequest.new, metadata: rpc_headers)
        unless res.is_a?(Collections::ListReply)
          raise Error::CollectionListFailure, "expected Collections::ListReply response, got #{res.class} instead"
        end

        res.collections.map { |c| decrypt_collection_info(c) }
      rescue ::GRPC::BadStatus => ex
        raise Error::CollectionListFailure, "Error while getting collection list: #{ex.message} (#{ex.class})"
      end

      def create_collection(name, metadata, indexes)
        res = stub.create_collection(
          Collections::CreateRequest.new(
            ref: @profile.ref_for(name),
            metadata: encrypt_blob(metadata.to_cbor),
            indexes: indexes.map do |idx|
              {
                id: blob_from_uuid(SecureRandom.uuid),
                settings: encrypt_blob(idx.to_cbor)
              }
            end
          ),
          metadata: rpc_headers
        )

        unless res.is_a?(Collections::InfoReply)
          raise Error::CollectionCreationFailure, "expected Collections::InfoReply response, got #{res.class} instead"
        end
      rescue ::GRPC::BadStatus => ex
        raise Error::CollectionCreateFailure, "Error while creating collection '#{name}': #{ex.message} (#{ex.class})"
      end

      def delete_collection(collection)
        res = stub.delete_collection(Collections::DeleteRequest.new(ref: collection.ref), metadata: rpc_headers)
        unless res.is_a?(Collections::InfoReply)
          raise Error::CollectionDeleteFailure, "expected Collections::InfoReply response, got #{res.class} instead"
        end

        true
      rescue ::GRPC::NotFound
        raise Error::CollectionDeleteFailure, "Collection '#{name}' not found"
      rescue ::GRPC::BadStatus => ex
        raise Error::CollectionDeleteFailure, "Error while deleting collection '#{name}': #{ex.message} (#{ex.class})"
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
      rescue ::GRPC::NotFound
        raise Error::RecordPutFailure, "Collection '#{collection.name}' not found"
      rescue ::GRPC::BadStatus => ex
        raise Error::RecordPutFailure, "Error while putting records into collection '#{collection.name}': #{ex.message} (#{ex.class})"
      end

      def get(collection, id)
        res = stub.get(Documents::GetRequest.new(collectionId: blob_from_uuid(collection.id), id: blob_from_uuid(id)), metadata: rpc_headers)
        unless res.is_a?(Documents::GetReply)
          raise Error::RecordGetFailure, "expected Documents::GetReply response, got #{res.class} instead"
        end

        decrypt_record(res.source)
      rescue ::GRPC::NotFound
        raise Error::RecordGetFailure, "Collection '#{collection.name}' not found"
      rescue ::GRPC::BadStatus => ex
        raise Error::RecordGetFailure, "Error while getting records from collection '#{collection.name}': #{ex.message} (#{ex.class})"
      end

      def get_all(collection, ids)
        res = stub.get_all(Documents::GetAllRequest.new(collectionId: blob_from_uuid(collection.id), ids: ids.map { |x| blob_from_uuid(x) }), metadata: rpc_headers)
        unless res.is_a?(Documents::GetAllReply)
          raise Error::RecordGetFailure, "expected Documents::GetAllReply response, got #{res.class} instead"
        end

        res.documents.map { |r| decrypt_record(r) }
      rescue ::GRPC::NotFound
        raise Error::RecordGetFailure, "Collection '#{collection.name}' not found"
      rescue ::GRPC::BadStatus => ex
        raise Error::RecordGetFailure, "Error while getting records from collection '#{collection.name}': #{ex.message} (#{ex.class})"
      end

      def delete(collection, id)
        res = stub.delete(Documents::DeleteRequest.new(collectionId: blob_from_uuid(collection.id), id: blob_from_uuid(id)), metadata: rpc_headers)
        unless res.is_a?(Documents::DeleteReply)
          raise Error::RecordDeleteFailure, "expected Documents::DeleteReply response, got #{res.class} instead"
        end

        true
      rescue ::GRPC::NotFound
        raise Error::RecordDeleteFailure, "Collection '#{collection.name}' not found"
      rescue ::GRPC::BadStatus => ex
        raise Error::RecordDeleteFailure, "Error while deleting record from collection '#{collection.name}': #{ex.message} (#{ex.class})"
      end

      def query(collection, q)
        res = stub.query(Queries::QueryRequest.new(collectionId: blob_from_uuid(collection.id), query: q), metadata: rpc_headers)

        unless res.is_a?(Queries::QueryReply)
          raise Error::RecordDeleteFailure, "expected Queries::QueryReply response, got #{res.class} instead"
        end

        Collection::QueryResult.new(res.records.map { |r| decrypt_record(r) }, res.aggregates)
      rescue ::GRPC::NotFound
        raise Error::DocumentQueryFailure, "Collection '#{collection.name}' not found"
      rescue ::GRPC::BadStatus => ex
        raise Error::DocumentQueryFailure, "Error while querying collection '#{collection.name}': #{ex.message} (#{ex.class})"
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
        @profile.with_access_token do |creds|
          { authorization: "Bearer #{creds[:access_token]}" }
        end
      end

      def decrypt_collection_info(info)
        unless info.is_a?(Collections::InfoReply)
          raise Error::DecryptionFailure, "expected Collections::InfoReply, got #{info.class} instead"
        end

        Collection.new(
          self,
          uuid_from_blob(info.id),
          info.ref,
          metadata = CBOR.decode(@cipher_engine.decrypt(Enveloperb::EncryptedRecord.new(info.metadata))),
          info.indexes.map { |i| decrypt_index(i) }
        )
      end

      def decrypt_index(idx)
        unless idx.is_a?(Indexes::Index)
          raise Error::DecryptionFailure, "expected Indexes::Index, got #{idx.class} instead"
        end

        Index.generate(
          uuid_from_blob(idx.id),
          CBOR.decode(@cipher_engine.decrypt(Enveloperb::EncryptedRecord.new(idx.settings)))
        )
      end

      def decrypt_record(r)
        unless r.is_a?(Documents::Document)
          raise Error::DecryptionFailure, "expected Documents::Document, got #{r.class} instead"
        end

        Record.new(
          uuid_from_blob(r.id),
          r.source == "" ? nil : CBOR.unpack(@cipher_engine.decrypt(Enveloperb::EncryptedRecord.new(r.source)))
        )
      end

      def uuid_from_blob(blob)
        blob.unpack("H*").first.scan(/^(.{8})(.{4})(.{4})(.{4})(.*)$/).join("-")
      end

      def blob_from_uuid(uuid)
        [uuid.gsub("-", "")].pack("H*")
      end

      def encrypt_blob(blob)
        @cipher_engine.encrypt(blob).to_s
      end
    end

    private_constant :RPC
  end
end
