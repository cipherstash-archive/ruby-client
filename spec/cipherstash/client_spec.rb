require_relative "../spec_helper"

require "cipherstash/client"

describe CipherStash::Client do
  include FakeFS::SpecHelpers

  describe ".new" do
    before(:each) do
      create_fake_profile("default")
      create_fake_profile("envious")
      create_fake_profile("filing")
      create_fake_profile("argumentative")
    end

    def profile(client)
      client.instance_variable_get(:@profile)
    end

    def data(profile)
      profile.instance_variable_get(:@data)
    end

    it "reads the default profile by default" do
      expect(profile(described_class.new).name).to eq("default")
    end

    it "reads the profile specified in config.json if specified" do
      File.write(File.expand_path("~/.cipherstash/config.json"), '{"defaultProfile":"filing"}')
      expect(profile(described_class.new).name).to eq("filing")
    end

    it "reads an alternate profile if specified by profileName" do
      expect(profile(described_class.new(profileName: "argumentative")).name).to eq("argumentative")
    end

    it "reads an alternate profile if specified by CS_PROFILE_NAME" do
      with_env("CS_PROFILE_NAME" => "envious") do
        expect(profile(described_class.new).name).to eq("envious")
      end
    end

    it "prefers profileName to config.json" do
      File.write(File.expand_path("~/.cipherstash/config.json"), '{"defaultProfile":"filing"}')
      expect(profile(described_class.new(profileName: "argumentative")).name).to eq("argumentative")
    end

    it "prefers profileName to CS_PROFILE_NAME" do
      with_env("CS_PROFILE_NAME" => "envious") do
        expect(profile(described_class.new(profileName: "argumentative")).name).to eq("argumentative")
      end
    end

    it "prefers CS_PROFILE_NAME to config.json" do
      File.write(File.expand_path("~/.cipherstash/config.json"), '{"defaultProfile":"filing"}')
      with_env("CS_PROFILE_NAME" => "envious") do
        expect(profile(described_class.new).name).to eq("envious")
      end
    end

    it "explodes if the profile named doesn't exist" do
      expect { described_class.new(profileName: "nonexistent") }.to raise_error(CipherStash::Client::Error::LoadProfileFailure)
    end

    xit "overrides workspace if provided" do
      expect(data(described_class.new(workspace: "FLIBBETYGIBBETS"))["workspace"]).to eq("FLIBBETYGIBBETS")
    end

    it "overrides serviceFqdn if provided"
    it "overrides servicePort if provided"
    it "overrides serviceTrustAnchor if provided"
    it "overrides idpHost if provided"
    it "overrides idpClientId if provided"
    it "overrides idpClientSecret if provided"
    it "overrides accessToken if provided"
    it "overrides kmsKeyArn if provided"
    it "overrides kmsKeyRegion if provided"
    it "overrides namingKey if provided"
    it "overrides kmsFederationRoleArn if provided"
    it "overrides awsAccessKeyId if provided"
    it "overrides awsSecretAccessKey if provided"
    it "overrides awsRegion if provided"

    context "with a metrics collector" do
      let(:metrics) { described_class::Metrics::Hash.new }
      let!(:client) { described_class.new(metrics: metrics) }

      it "doesn't explode" do
        expect { client }.to_not raise_error
      end

      it "registers the client start time" do
        expect(metrics).to respond_to(:[])
        expect(metrics[:creation_timestamp_seconds]).to be_a(Hash)
        p metrics[:creation_timestamp_seconds]
        expect(metrics[:creation_timestamp_seconds][{}]).to be_within(0.1).of(Time.now.to_f)
      end
    end
  end

  describe ".create_collection" do
    before(:all) { create_fake_profile("default") }

    let(:rpc) { instance_double("RPC") }
    let(:rpc_class) { double(new: rpc) }
    let(:client) { described_class.new(rpc_class: rpc_class) }

    it "passes through name, metadata, and indexes to the RPC client" do
      expect(rpc).to receive(:create_collection).with("empty", {:name=>"empty", :recordType=>{}}, [])

      client.create_collection("empty", {})
    end

    [
      ["match", "filter-match"],
      ["filter-match", "filter-match"],
      ["ore-match", "ore-match"],
      ["dynamic-match", "dynamic-filter-match"],
      ["dynamic-filter-match", "dynamic-filter-match"],
      ["dynamic-ore-match", "dynamic-ore-match"],
      ["field-dynamic-match", "field-dynamic-filter-match"],
      ["field-dynamic-filter-match", "field-dynamic-filter-match"],
      ["field-dynamic-ore-match", "field-dynamic-ore-match"],
    ].each do |input_kind, expected_kind|
      context "given a schema with a #{input_kind} index" do
        def schema(kind)
          mapping = {
            "kind" => kind,
            "tokenFilters" => [{"kind" => "downcase"}, {"kind" => "ngram", "minLength" => 3, "maxLength" => 8}],
            "tokenizer" => {"kind" => "standard"}
          }

          if ["match", "ore-match", "filter-match"].include?(kind)
            mapping["fields"] = ["title"]
          end

          {
            "type" => {"title" => "string"},
            "indexes" => {
              "title" => mapping,
            },
          }
        end

        it "sets mapping fieldType to string in the RPC call" do
          schema = schema(input_kind)

          expect(rpc).to receive(:create_collection).with(
            anything,
            anything,
            array_including(hash_including(mapping: hash_including("fieldType" => "string")))
          )

          client.create_collection("name", schema)
        end

        it "sets mapping kind to #{expected_kind} in the RPC call" do
          schema = schema(input_kind)

          expect(rpc).to receive(:create_collection).with(
            anything,
            anything,
            array_including(hash_including(mapping: hash_including("kind" => expected_kind)))
          )

          client.create_collection("name", schema)
        end
      end
    end

    ["exact", "range"].each do |input_kind|
      context "given a schema with a #{input_kind} index" do
        def schema(kind)
          mapping = {
            "kind" => kind,
            "field" => "title",
            "unique" => true
          }

          {
            "type" => {"title" => "string"},
            "indexes" => {
              "exactTitle" => mapping,
            },
          }
        end

        it "can specify field as unique" do
          schema = schema(input_kind)

          expect(rpc).to receive(:create_collection).with(
            anything,
            anything,
            array_including(hash_including(mapping: hash_including("unique" => true)))
          )

          client.create_collection("name", schema)
        end
      end
    end

    [
      "match",
      "ore-match",
      "filter-match",
      "field-dynamic-match",
      "field-dynamic-filter-match",
      "field-dynamic-ore-match",
      "dynamic-match",
      "dynamic-filter-match",
      "dynamic-ore-match"].each do |input_kind|
      context "given a schema with a #{input_kind} index" do
        def schema(kind)
          mapping = {
            "kind" => kind,
            "field" => "title",
            "unique" => true
          }

          {
            "type" => {"title" => "string"},
            "indexes" => {
              "title" => mapping,
            },
          }
        end

        it "can not specify field as unique" do
          schema = schema(input_kind)

          expect { client.create_collection("name", schema) }.to raise_error(CipherStash::Client::Error::InvalidSchemaError)
        end
      end
    end
  end
end
