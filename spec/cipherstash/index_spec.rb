require_relative "../spec_helper"

require "logger"

require "cipherstash/index"

describe CipherStash::Index do
  describe ".generate" do
    def match_settings(id, kind)
      {
        "meta" => {
          "$indexId" => id,
          "$indexName" => "title",
          "$prfKey" => "prf-key",
          "$prpKey"=> "prp-key",
        },
        "mapping" => {
          "kind" => kind,
          "fields" => ["title"],
          "tokenFilters" => [{"kind"=>"downcase"}, {"kind"=>"ngram", "tokenLength"=>3}],
          "tokenizer" => {"kind"=>"standard"},
          "fieldType" => "string",
        }
      }
    end

    def dynamic_match_settings(id, kind)
      {
        "meta" => {
          "$indexId" => id,
          "$indexName" => "title",
          "$prfKey" => "prf-key",
          "$prpKey"=> "prp-key",
        },
        "mapping" => {
          "kind" => kind,
          "tokenFilters" => [{"kind"=>"downcase"}, {"kind"=>"ngram", "tokenLength"=>3}],
          "tokenizer" => {"kind"=>"standard"},
          "fieldType" => "string",
        }
      }
    end

    let(:id) { SecureRandom.uuid }
    let(:schema_versions) { {:first=>0, :last=>0, :searchable=>true} }

    context "given a match kind" do
      it "generates an OreMatch index" do
        kind = "match"
        settings = match_settings(id, kind)

        index = described_class.generate(id, settings, schema_versions)

        expect(index).to be_an_instance_of(CipherStash::Index::OreMatch)
      end
    end

    context "given a dynamic-match kind" do
      it "generates a DynamicOreMatch index" do
        kind = "dynamic-match"
        settings = dynamic_match_settings(id, kind)

        index = described_class.generate(id, settings, schema_versions)

        expect(index).to be_an_instance_of(CipherStash::Index::DynamicOreMatch)
      end
    end

    context "given a field-dynamic-match kind" do
      it "generates a FieldDynamicOreMatch index" do
        kind = "field-dynamic-match"
        settings = dynamic_match_settings(id, kind)

        index = described_class.generate(id, settings, schema_versions)

        expect(index).to be_an_instance_of(CipherStash::Index::FieldDynamicOreMatch)
      end
    end

    context "given an ore-match kind" do
      it "generates an OreMatch index" do
        kind = "ore-match"
        settings = match_settings(id, kind)

        index = described_class.generate(id, settings, schema_versions)

        expect(index).to be_an_instance_of(CipherStash::Index::OreMatch)
      end
    end

    context "given a dynamic-ore-match kind" do
      it "generates a DynamicOreMatch index" do
        kind = "dynamic-ore-match"
        settings = dynamic_match_settings(id, kind)

        index = described_class.generate(id, settings, schema_versions)

        expect(index).to be_an_instance_of(CipherStash::Index::DynamicOreMatch)
      end
    end

    context "given a field-dynamic-ore-match kind" do
      it "generates a FieldDynamicOreMatch index" do
        kind = "field-dynamic-ore-match"
        settings = dynamic_match_settings(id, kind)

        index = described_class.generate(id, settings, schema_versions)

        expect(index).to be_an_instance_of(CipherStash::Index::FieldDynamicOreMatch)
      end
    end

    context "given a filter-match kind" do
      it "generates an FilterMatch index" do
        kind = "filter-match"
        settings = match_settings(id, kind)

        index = described_class.generate(id, settings, schema_versions)

        expect(index).to be_an_instance_of(CipherStash::Index::FilterMatch)
      end
    end

    context "given a dynamic-filter-match kind" do
      it "generates an DynamicFilterMatch index" do
        kind = "dynamic-filter-match"
        settings = match_settings(id, kind)

        index = described_class.generate(id, settings, schema_versions)

        expect(index).to be_an_instance_of(CipherStash::Index::DynamicFilterMatch)
      end
    end

    context "given a field-dynamic-filter-match kind" do
      it "generates an FieldDynamicFilterMatch index" do
        kind = "field-dynamic-filter-match"
        settings = match_settings(id, kind)

        index = described_class.generate(id, settings, schema_versions)

        expect(index).to be_an_instance_of(CipherStash::Index::FieldDynamicFilterMatch)
      end
    end
  end
end
