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

      def initialize(collection)
        @collection = collection
      end

      # Run the block passed to a #query and sling back a Query protobuf ready to rock and/or roll.
      def parse(&blk)
        qc = QueryCollector.new(@collection)
        yield qc

        Queries::Query.new(
          limit: 50,
          constraints: qc.__constraints,
          aggregates: [],
          ordering: [],
          skipResults: false,
          offset: 0
        )
      end

      class QueryCollector < BasicObject
        attr_reader :__constraints

        def initialize(collection)
          @collection = collection
          @__constraints = []
          @index = nil
        end

        # @private
        def method_missing(name, *args)
          if @index
            if @index.supports?(name.to_s)
              @__constraints += @index.generate_constraints(name.to_s, *args)
              @index = nil
            else
              ::Kernel.raise ::NoMethodError, "unknown operator `#{name}' for index '#{@index.name}'"
            end
          else
            @index = @collection.index_named(name.to_s)

            if @index.nil?
              ::Kernel.raise ::NoMethodError, "undefined index `#{name}' for collection '#{@collection.name}'"
            end
          end

          self
        end
      end

      private_constant :QueryCollector
    end
  end
end
