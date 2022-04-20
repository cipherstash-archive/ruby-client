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
  end
end
