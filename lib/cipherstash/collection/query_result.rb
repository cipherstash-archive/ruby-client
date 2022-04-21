module CipherStash
  class Collection
    # The result set that comes from a query.
    class QueryResult
      # The set of records which was considered pertinent to the query.
      #
      # @return [Array<CipherStash::Record>]
      #
      attr_reader :records

      # The aggregates that were derived from the query.
      #
      # @return [Array<CipherStash::Aggregate>]
      #
      attr_reader :aggregates

      # @private
      def initialize(records, aggregates)
        @records, @aggregates = records, aggregates
      end
    end
  end
end
