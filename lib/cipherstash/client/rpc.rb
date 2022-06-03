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
                id: blob_from_uuid(idx[:meta]["$indexId"]),
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

      def migrate_collection(name, metadata, indexes, from_schema_version)
        res = stub.migrate_collection(
          Collections::MigrateRequest.new(
            ref: @profile.ref_for(name),
            metadata: encrypt_blob(metadata.to_cbor),
            indexes: indexes.map do |idx|
              {
                id: blob_from_uuid(idx[:meta]["$indexId"]),
                settings: encrypt_blob(idx.to_cbor)
              }
            end,
            fromSchemaVersion: from_schema_version
          ),
          metadata: rpc_headers
        )

        unless res.is_a?(Collections::MigrateReply)
          raise Error::CollectionMigrateFailure, "expected Collections::InfoReply response, got #{res.class} instead"
        end

        raise_if_error(res)
      rescue ::GRPC::BadStatus => ex
        raise Error::CollectionMigrateFailure, "Error while migrating collection '#{name}': #{ex.message} (#{ex.class})"
      end

      def delete_collection(collection)
        res = stub.delete_collection(Collections::DeleteRequest.new(ref: collection.ref), metadata: rpc_headers)
        unless res.is_a?(Collections::InfoReply)
          raise Error::CollectionDeleteFailure, "expected Collections::InfoReply response, got #{res.class} instead"
        end

        true
      rescue ::GRPC::NotFound
        raise Error::CollectionDeleteFailure, "Collection '#{collection.name}' not found"
      rescue ::GRPC::BadStatus => ex
        raise Error::CollectionDeleteFailure, "Error while deleting collection '#{collection.name}': #{ex.message} (#{ex.class})"
      end

      def put(collection, id, record, vectors)
        res = stub.put(
          Documents::PutRequest.new(
            collectionId: blob_from_uuid(collection.id),
            source: { id: blob_from_uuid(id), source: record.nil? ? "" : encrypt_blob(record.to_cbor) },
            vectors: vectors,
            firstSchemaVersion: collection.first_active_schema_version,
            lastSchemaVersion: collection.current_schema_version
          ),
          metadata: rpc_headers
        )

        unless res.is_a?(Documents::PutReply)
          raise Error::RecordPutFailure, "expected Documents::PutReply response, got #{res.class} instead"
        end

        raise_if_error(res)

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

      def migrate_records(collection)
        requests = Queue.new
        class << requests
          def each
            loop do
              item = pop
              break if closed?
              yield item
            end
          end
        end

        @logger.debug("CipherStash::Client::RPC#migrate_records") { "Sending :Init" }
        requests.push(
          Documents::MigrateRequest.new(
            type: :Init,
            collectionId: blob_from_uuid(collection.id),
            firstSchemaVersion: collection.first_active_schema_version,
            lastSchemaVersion: collection.current_schema_version
          )
        )

        stub.migrate_records(requests, metadata: rpc_headers).each do |res|
          @logger.debug("CipherStash::Client::RPC#migrate_records") { "Received reply of type #{res.type.inspect}" }
          if res.type == :Barrier
            @logger.debug("CipherStash::Client::RPC#migrate_records") { "Sending barrier" }
            requests.push Documents::MigrateRequest.new(type: :Barrier)
          elsif res.type == :Done
            @logger.debug("CipherStash::Client::RPC#migrate_records") { "Closing request queue" }
            requests.close
          elsif res.type == :Record
            if res.record.source == ""
              raise Error::RecordMigrateFailure, "Cannot migrate record with empty source"
            end

            doc = CBOR.unpack(cipher_engine.decrypt(Enveloperb::EncryptedRecord.new(res.record.source)))

            @logger.debug("CipherStash::Client::RPC#migrate_records") { "Sending re-indexed record" }
            requests.push Documents::MigrateRequest.new(type: :Record, record: { id: res.record.id, source: res.record.source }, vectors: yield(uuid_from_blob(res.record.id), doc))
          else
            raise Error::RecordMigrateFailure, "Received unexpected MigrateReply: #{res.inspect}"
          end
        end
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
        res = stub.query(Queries::QueryRequest.new(collectionId: blob_from_uuid(collection.id), query: q, schemaVersion: collection.last_active_schema_version), metadata: rpc_headers)

        unless res.is_a?(Queries::QueryReply)
          raise Error::RecordDeleteFailure, "expected Queries::QueryReply response, got #{res.class} instead"
        end

        raise_if_error(res)

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
        { authorization: "Bearer #{@profile.with_access_token[:access_token]}" }
      end

      def decrypt_collection_info(info)
        unless info.is_a?(Collections::InfoReply)
          raise Error::DecryptionFailure, "expected Collections::InfoReply, got #{info.class} instead"
        end

        metadata = begin
                     CBOR.decode(cipher_engine.decrypt(Enveloperb::EncryptedRecord.new(info.metadata)))
                   rescue => ex
                     @logger.warn("CipherStash::Client::RPC#decrypt_collection_info") { "Failed to decrypt collection metadata: #{ex.message} (#{ex.class})" }
                     {}
                   end

        Collection.new(
          self,
          uuid_from_blob(info.id),
          info.ref,
          metadata,
          info.indexes.map do |idx|
            begin
              decrypt_index(idx, info.lastActiveSchemaVersion)
            rescue => ex
              @logger.warn("CipherStash::Client::RPC#decrypt_collection_info") { "Failed to decrypt index #{uuid_from_blob(idx.id)}: #{ex.message} (#{ex.class})" }
              nil
            end
          end,
          schema_versions: {
            current: info.currentSchemaVersion,
            first_active: info.firstActiveSchemaVersion,
            last_active: info.lastActiveSchemaVersion
          },
          logger: @logger
        )
      end

      def decrypt_index(idx, last_active_schema_version)
        unless idx.is_a?(Indexes::Index)
          raise Error::DecryptionFailure, "expected Indexes::Index, got #{idx.class} instead"
        end

        Index.generate(
          uuid_from_blob(idx.id),
          CBOR.decode(cipher_engine.decrypt(Enveloperb::EncryptedRecord.new(idx.settings))),
          { first: idx.firstSchemaVersion, last: idx.lastSchemaVersion, searchable: idx.firstSchemaVersion <= last_active_schema_version }
        )
      end

      def decrypt_record(r)
        unless r.is_a?(Documents::Document)
          raise Error::DecryptionFailure, "expected Documents::Document, got #{r.class} instead"
        end

        Record.new(
          uuid_from_blob(r.id),
          r.source == "" ? nil : CBOR.unpack(cipher_engine.decrypt(Enveloperb::EncryptedRecord.new(r.source)))
        )
      end

      def uuid_from_blob(blob)
        blob.unpack("H*").first.scan(/^(.{8})(.{4})(.{4})(.{4})(.*)$/).join("-")
      end

      def blob_from_uuid(uuid)
        [uuid.gsub("-", "")].pack("H*")
      end

      def encrypt_blob(blob)
        cipher_engine.encrypt(blob).to_s
      end

      def cipher_engine
        @cipher_engine ||= @profile.cipher_engine
      end

      def raise_if_error(res)
        if res.error != :NoError
          case res.error
          when :ErrUnknownSchemaVersion
            raise Error::UnknownSchemaVersionError
          when :ErrObsoleteSchemaVersion
            raise Error::ObsoleteSchemaVersionError
          when :ErrIncompleteSchemaVersionCoverage
            raise Error::IncompleteSchemaVersionCoverageError
          else
            raise Error::InternalError, "Oops, got an error we don't properly handle: #{res.error}"
          end
        end
      end
    end

    private_constant :RPC
  end
end
