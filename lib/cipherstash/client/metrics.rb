module CipherStash
  class Client
    # A generic interface to the metrics of a CipherStash client.
    #
    # We try to collect comprehensive numeric information about the performance
    # and behaviour of a CipherStash client, which are collected into a Metrics
    # instance.  This instance, depending on what sort it is, can either expose
    # the metrics for collection at a point convenient to the code that uses
    # the client (as the Hash metrics subclass does), or it can feed the
    # numeric data directly to something that exposes said data to an external
    # system for periodic collection (the Prometheus metrics subclass does
    # this).
    #
    # You should not use this class directly; instead, you should instantiate the
    # appropriate subclass in this namespace for your needs.
    #
    # # Available Metrics
    #
    # A CipherStash::Client::Metrics instance provides the following metrics:
    #
    # * `creation_timestamp_seconds` (gauge) the (floating-point) number of seconds since the Unix epoch at which this instance of CipherStash::Client was created.
    #
    # * `method_time_total_seconds` (counter) the (floating-point) number of seconds that have been spent in all calls to this client and its collections.
    #   Labelled by the method name.
    #
    # * `rpc_time_total_seconds` (counter) the (floating-point) number of seconds that this client has spent making RPC calls to the data-service.
    #   Labelled by the RPC operation being undertaken.
    #
    # * `crypto_time_total_seconds` (counter) the (floating-point) number of seconds that the client has spent performing cryptographic operations, including communicating with an external key-management service (if appropriate).
    #   Labelled by the operation ("encrypt" or "decrypt") and RPC involved.
    #
    class Metrics
      # @private
      def initialize(registry, metrics_prefix: "", base_labels: {})
        @registry = registry
        @base_labels = base_labels

        @metrics = {}
        @measurement_exclusions = ::Hash.new(0)

        register_metrics(metrics_prefix)
      end

      # @private
      def created
        @metrics[:creation_timestamp_seconds].set(Time.now.to_f, labels: @base_labels)
      end

      # @private
      def measure_client_call(name, mode = :included, &blk)
        measure(:method_time_total_seconds, mode, method: name, &blk)
      end

      # @private
      def measure_rpc_call(rpc, mode = :included, &blk)
        measure(:rpc_time_total_seconds, mode, rpc: rpc, &blk)
      end

      # @private
      def measure_crypto_call(op, rpc, mode = :included, &blk)
        measure(:crypto_time_total_seconds, mode, op: op, rpc: rpc, &blk)
      end

      private

      def register_metrics(prefix)
        base_labels_keys = @base_labels.keys

        @metrics[:creation_timestamp_seconds] = @registry.gauge(:"#{prefix}creation_timestamp_seconds", docstring: "When this instance of CipherStash::Client was created", labels: base_labels_keys)
        @metrics[:method_time_total_seconds]  = @registry.counter(:"#{prefix}method_time_total_seconds", docstring: "The amount of time spent in client code", labels: (base_labels_keys + [:method]).uniq)
        @metrics[:rpc_time_total_seconds]     = @registry.counter(:"#{prefix}rpc_time_total_seconds", docstring: "The amount of time spent executing RPCs", labels: (base_labels_keys + [:rpc]).uniq)
        @metrics[:crypto_time_total_seconds]  = @registry.counter(:"#{prefix}rpc_time_total_seconds", docstring: "The amount of time spent doing cryptographic operations", labels: (base_labels_keys + [:op, :rpc]).uniq)
      end

      def measure(metric, mode, **labels)
        start_time = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        rv = yield
        case mode
        when :included
          @metrics[metric].increment(by: Process.clock_gettime(Process::CLOCK_MONOTONIC) - start_time - @measurement_exclusions[metric], labels: @base_labels.merge(labels))
          @measurement_exclusions.delete(metric)
        when :excluded
          @measurement_exclusions[metric] += Process.clock_gettime(Process::CLOCK_MONOTONIC) - start_time
        else
          raise ArgumentError, "Unknown measurement mode: #{mode.inspect}"
        end

        rv
      end


      # A CipherStash::Client::Metrics collector that does nothing.
      #
      # You don't want to use this in your code, it's just to give CipherStash::Client
      # something to use if a metrics collector isn't specified.
      #
      # @private
      #
      class Null < Metrics
        def initialize
          super(Registry.new)
        end

        class Registry
          def counter(*_opts)
            Object.new.tap do |obj|
              class << obj
                def increment(*_opts)
                end
              end
            end
          end

          def gauge(*_opts)
            Object.new.tap do |obj|
              class << obj
                def set(*_opts)
                end
              end
            end
          end
        end
      end

      # A CipherStash::Client::Metrics collector that aggregates metrics in a hash.
      #
      # Pass this metrics instance into a CipherStash::Client like this:
      #
      # ```
      # metrics = CipherStash::Client::Metrics::Hash.new
      # client = CipherStash::Client.new(metrics: metrics)
      # ```
      #
      # Then after you've used your client object, you can simply examine all the metrics like so:
      #
      # ```
      # pp metrics
      # ```
      #
      # This will dump out everything in a big hash, just like magic.
      # For details of all the metrics and what they mean, see the [CipherStash::Client::Metrics] documentation.
      #
      class Hash < Metrics
        def initialize
          @metrics = {}
          super(Registry.new(@metrics))
        end

        def [](k)
          @metrics[k]
        end

        # Do not look behind the curtain!
        #
        # @private
        def pretty_print(q)  # :nodoc:
          @metrics.pretty_print(q)
        end

        class Registry
          def initialize(hash)
            @hash = hash
          end

          def counter(name, docstring:, labels:)
            h = ::Hash.new(0)

            class << h
              def increment(by: 1, labels: {})
                self[labels] += by
              end
            end
            @hash[name.to_sym] = h
          end

          def gauge(name, docstring:, labels:)
            h = ::Hash.new
            class << h
              def set(v, labels: {})
                self[labels] = v
              end
            end
            @hash[name.to_sym] = h
          end
        end
        private_constant :Registry
      end
    end
  end
end
