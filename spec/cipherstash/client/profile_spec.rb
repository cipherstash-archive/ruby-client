require_relative "../../spec_helper"

require "logger"

require "cipherstash/client/profile"

describe CipherStash::Client::Profile do
  include FakeFS::SpecHelpers

  before(:each) do
    create_fake_profile("default")
  end

  let(:logger) { Logger.new($stderr).tap { |l| l.level = Logger::WARN } }
  let(:profile_name) { "default" }
  let(:profile) { described_class.load(profile_name, logger) }
  let(:data) { profile.instance_variable_get(:@data) }

  describe ".load" do
    context "when no profile was specified and the default profile doesn't exist" do
      let(:profile_name) { nil }

      before(:each) do
        FileUtils.rm_rf(File.expand_path("~/.cipherstash/default"))
      end

      it "loads OK" do
        expect { described_class.load(profile_name, logger) }.to_not raise_error
      end
    end

    context "when the default profile was specified but it does not exist" do
      let(:profile_name) { "default" }

      before(:each) do
        FileUtils.rm_rf(File.expand_path("~/.cipherstash/default"))
      end

      it "raises an error" do
        expect { described_class.load(profile_name, logger) }.to raise_error(CipherStash::Client::Error::LoadProfileFailure)
      end
    end

    context "on a profile that does not exist" do
      let(:profile_name) { "non-existent" }

      it "raises an error" do
        expect { described_class.load(profile_name, logger) }.to raise_error(CipherStash::Client::Error::LoadProfileFailure)
      end
    end

    context "on a profile that exists" do
      before(:each) do
        create_fake_profile(profile_name)
      end

      it "loads successfully" do
        expect { described_class.load(profile_name, logger) }.to_not raise_error
      end

      it "stores the profile name" do
        expect(profile.name).to eq(profile_name)
      end
    end

    context "with environment variables" do
      it "prefers CS_WORKSPACE" do
        with_env("CS_WORKSPACE" => "FL18837YG18837S") do
          expect(data["service"]["workspace"]).to eq("FL18837YG18837S")
        end
      end

      it "prefers CS_SERVICE_FQDN" do
        with_env("CS_SERVICE_FQDN" => "flibbety.example.com") do
          expect(data["service"]["host"]).to eq("flibbety.example.com")
        end
      end

      it "prefers CS_SERVICE_PORT" do
        with_env("CS_SERVICE_PORT" => "31337") do
          expect(data["service"]["port"]).to eq(31337)
        end
      end

      it "prefers CS_SERVICE_TRUST_ANCHOR" do
        with_env("CS_SERVICE_TRUST_ANCHOR" => "-----BEGIN FLIBBETYGIBBETS-----") do
          expect(data["service"]["trustAnchor"]).to eq("-----BEGIN FLIBBETYGIBBETS-----")
        end
      end

      it "prefers CS_IDP_HOST" do
        with_env("CS_IDP_HOST" => "https://gibbets.example.com/") do
          expect(data["identityProvider"]["host"]).to eq("https://gibbets.example.com/")
        end
      end

      it "prefers CS_IDP_CLIENT_ID" do
        with_env("CS_IDP_CLIENT_ID" => "argleFargle") do
          expect(data["identityProvider"]["clientId"]).to eq("argleFargle")
        end
      end

      it "prefers CS_IDP_CLIENT_SECRET" do
        with_env("CS_IDP_CLIENT_SECRET" => "squirrel") do
          expect(data["identityProvider"]["clientSecret"]).to eq("squirrel")
        end
      end

      it "prefers CS_ACCESS_TOKEN" do
        with_env("CS_ACCESS_TOKEN" => "toketoketoke") do
          expect(data["identityProvider"]["accessToken"]).to eq("toketoketoke")
        end
      end

      it "prefers CS_KMS_KEY_ARN" do
        with_env("CS_KMS_KEY_ARN" => "arn:aws:aaaaaaaaaaaaaaaaaaaaaaaaaargh") do
          expect(data["keyManagement"]["key"]["arn"]).to eq("arn:aws:aaaaaaaaaaaaaaaaaaaaaaaaaargh")
        end
      end

      it "prefers CS_KMS_KEY_REGION" do
        with_env("CS_KMS_KEY_REGION" => "ap-biteme-1") do
          expect(data["keyManagement"]["key"]["region"]).to eq("ap-biteme-1")
        end
      end

      it "prefers CS_NAMING_KEY" do
        with_env("CS_NAMING_KEY" => "AAAAAAAAAAAAAAAAAAAAAAARGH") do
          expect(data["keyManagement"]["key"]["namingKey"]).to eq("AAAAAAAAAAAAAAAAAAAAAAARGH")
        end
      end

      it "prefers CS_KMS_FEDERATION_ROLE_ARN" do
        with_env("CS_KMS_FEDERATION_ROLE_ARN" => "arn:kms:ffs:12345:role/flibbetygibbets") do
          expect(data["keyManagement"]["awsCredentials"]["roleArn"]).to eq("arn:kms:ffs:12345:role/flibbetygibbets")
        end
      end

      it "prefers CS_AWS_ACCESS_KEY_ID" do
        with_env("CS_AWS_ACCESS_KEY_ID" => "AKIABLERGH") do
          expect(data["keyManagement"]["awsCredentials"]["accessKeyId"]).to eq("AKIABLERGH")
        end
      end

      it "prefers CS_AWS_SECRET_ACCESS_KEY" do
        with_env("CS_AWS_SECRET_ACCESS_KEY" => "SECRETSECRETSECRET") do
          expect(data["keyManagement"]["awsCredentials"]["secretAccessKey"]).to eq("SECRETSECRETSECRET")
        end
      end

      it "prefers CS_AWS_REGION" do
        with_env("CS_AWS_REGION" => "ap-biteme-1") do
          expect(data["keyManagement"]["awsCredentials"]["region"]).to eq("ap-biteme-1")
        end
      end
    end
  end

  describe "#service_host" do
    it "hands back whatever is in service.host" do
      expect(profile.service_host).to eq("default.example.com")
    end
  end

  describe "#service_trust_anchor" do
    it "is unset by default" do
      expect(profile.service_trust_anchor).to eq(nil)
    end

    context "when set in the profile" do
      before(:each) do
        create_fake_profile("default") do |p|
          p["service"]["trustAnchor"] = "-----BEGIN BOLLOCKS-----"
        end
      end

      it "hands back what was in the profile" do
        expect(profile.service_trust_anchor).to eq("-----BEGIN BOLLOCKS-----")
      end
    end
  end

  describe "#with_access_token" do
    context "with identityProvider.kind=Auth0-AccessToken" do
      before(:each) do
        create_fake_profile("default") do |profile|
          profile["identityProvider"] = { "kind" => "Auth0-AccessToken", "accessToken" => "s3kr1t" }
        end
      end

      it "returns the access token in the profile" do
        expect(profile.with_access_token { |x| x }[:access_token]).to eq("s3kr1t")
      end
    end
  end
end
