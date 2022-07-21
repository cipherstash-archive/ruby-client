require "cipherstash/grpc"

require_relative "./result_filter"
require_relative "../uuid_helpers"

module CipherStash
  class Collection
    # The underlying contraption to make querying work.
    #
    # @private
    class Query
      include Stash::GRPC::V1

      def initialize(collection, opts = {})
        @collection = collection
        @opts = opts
      end

      # Run the block passed to a #query and sling back a Query protobuf ready to rock and/or roll.
      def parse(&blk)
        qc = QueryCollector.new(@collection)
        yield qc if block_given?

        request = Queries::Query.new(
          limit: @opts[:limit] || 50,
          constraints: qc.__constraints,
          aggregates: [],
          ordering: qc.__ordering,
          skipResults: false,
          offset: @opts[:offset] || 0
        )

        [request, qc.result_filter]
      end

      class QueryCollector < BasicObject
        attr_reader :__constraints, :__ordering, :result_filter

        def initialize(collection)
          @collection = collection
          @__constraints = []
          @__ordering = []
          @index = nil
          @result_filter = ResultFilter.new()
        end

        def order_by(index_name, direction = :ASC)
          index = fetch_index(index_name)

          # Check that the index supports ordering
          unless index.orderable?
            ::Kernel.raise ::CipherStash::Client::Error::QueryOrderingError, "index '#{index_name}' does not support ordering (must be a `range` type)"
          end

          unless [:ASC, :DESC].include?(direction)
            ::Kernel.raise ::CipherStash::Client::Error::QueryOrderingError, "ordering direction must be either :ASC or :DESC (got #{direction.inspect})"
          end

          @__ordering << { indexId: index.binid, direction: direction }
        end

        def add_constraint(index_name, operator, *args)
          index = fetch_index(index_name.to_s)

          unless index.supports?(operator.to_s)
            ::Kernel.raise ::CipherStash::Client::Error::QueryConstraintError, "unknown operator `#{operator}' for index '#{index_name}'"
          end

          if @index.respond_to?(:filter_fn)
            @result_filter.add(@index.filter_fn(*args))
          end

          @__constraints += index.generate_constraints(operator, *args)
        end

        # @private
        def method_missing(name, *args)
          if @index
            if @index.supports?(name.to_s)
              @__constraints += @index.generate_constraints(name.to_s, *args)

              if @index.respond_to?(:filter_fn)
                @result_filter.add(@index.filter_fn(*args))
              end

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

            unless index.searchable?
              ::Kernel.raise ::CipherStash::Client::Error::QueryConstraintError, "index `#{name}' for collection '#{@collection.name}' is not yet searchable (not all records in the collection have been re-indexed yet)"
            end

            index
          end
      end

      private_constant :QueryCollector
    end
  end
end
