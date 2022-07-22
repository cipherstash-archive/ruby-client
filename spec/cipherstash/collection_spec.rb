require_relative "../spec_helper"

require "cipherstash/collection"
require "cipherstash/client"
require "cipherstash/index"

module CipherStash
  class Client
    class RPC
      def rpc_headers
        {}
      end
    end
  end
end

describe CipherStash::Collection do
  describe "#query" do
    it "works" do
      create_fake_profile("default")
      logger = Logger.new("/dev/null")
      profile = CipherStash::Client::Profile.load("default", logger)
      metrics = CipherStash::Client::Metrics::Null.new
      rpc = CipherStash::Client::RPC.new(profile, logger, metrics)
      id = SecureRandom.uuid
      ref = "123"
      metadata = {"name"=>"movies", "recordType"=>{"title"=>"string", "runningTime"=>"float64", "year"=>"uint64"}}
      index_id = SecureRandom.uuid
      schema_versions = {:first=>0, :last=>0, :searchable=>true}
      index = CipherStash::Index::FilterMatch.new(
        index_id,
        {"meta"=>
          {"$indexId"=> index_id,
           "$indexName"=>"title",
           "$filterKey"=> SecureRandom.hex(32),
         },
         "mapping"=>{
          "kind"=>"filter-match",
          "field"=>"title",
          "fieldType"=>"string",
          "tokenFilters"=>[{"kind"=>"downcase"}, {"kind"=>"ngram", "tokenLength"=>3}],
          "tokenizer"=>{"kind"=>"standard"},
          }},
         schema_versions
      )
      collection = described_class.new(rpc, id, ref, metadata, [index], schema_versions: schema_versions, metrics: metrics)

      expect(collection).to be_instance_of(CipherStash::Collection)

      res = collection.query do |movie|
        movie.title.match("Enterprise")
      end
    end
  end
end
