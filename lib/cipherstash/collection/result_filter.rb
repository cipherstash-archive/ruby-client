module CipherStash
  class Collection
    class ResultFilter
      def initialize
        @filter_fns = []
      end

      def add(filter_fn)
        @filter_fns << filter_fn
      end

      def filter(records)
        records.filter do |record|
          # TODO: this could exit early at the first fn that doesn't match
          @filter_fns.map { |f| f.call(record) }.all?
        end
      end
    end
  end
end
