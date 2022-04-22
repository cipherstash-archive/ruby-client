require "cipherstash/grpc"

require_relative "../uuid_helpers"

module CipherStash
  class Collection
    # The underlying contraption to make querying work.
    #
    # @private
    class Query
      include Stash::GRPC::V1
      include UUIDHelpers

      def initialize(collection, opts = {})
        @collection = collection
        @opts = opts
      end

      # Run the block passed to a #query and sling back a Query protobuf ready to rock and/or roll.
      def parse(&blk)
        qc = QueryCollector.new(@collection)
        yield qc if block_given?

        Queries::Query.new(
          limit: @opts[:limit] || 50,
          constraints: qc.__constraints,
          aggregates: [],
          ordering: qc.__ordering,
          skipResults: false,
          offset: @opts[:offset] || 0
        )
      end

      class QueryCollector < BasicObject
        attr_reader :__constraints, :__ordering

        def initialize(collection)
          @collection = collection
          @__constraints = []
          @__ordering = []
          @index = nil
        end

        def order_by(index_name, direction = :ASC)
          index = fetch_index(index_name)

          # Check that the index supports ordering
          unless index.supports?("range")
            ::Kernel.raise ::CipherStash::Client::Error::QueryOrderingError, "index '#{index_name}' does not support ordering (must be a `range` type)"
          end
          @__ordering << { indexId: UUIDHelpers.blob_from_uuid(index.id), direction: direction }
        end

        def add_constraint(index_name, operator, *args)
          index = fetch_index(index_name.to_s)

          unless index.supports?(operator.to_s)
            ::Kernel.raise ::CipherStash::Client::Error::QueryConstraintError, "unknown operator `#{operator}' for index '#{index_name}'"
          end

          @__constraints += index.generate_constraints(operator, *args)
        end

        # @private
        def method_missing(name, *args)
          if @index
            if @index.supports?(name.to_s)
              @__constraints += @index.generate_constraints(name.to_s, *args)
              @index = nil
            else
              ::Kernel.raise ::CipherStash::Client::Error::QueryConstraintError, "unknown operator `#{name}' for index '#{@index.name}'"
            end
          else
            @index = fetch_index(name.to_s)
          end

          self
        end

        private
          def fetch_index(name)
            index = @collection.index_named(name.to_s)

            if index.nil?
              ::Kernel.raise ::CipherStash::Client::Error::QueryConstraintError, "undefined index `#{name}' for collection '#{@collection.name}'"
            end

            index
          end
      end

      private_constant :QueryCollector
    end
  end
end
