require "fileutils"

module ExampleMethods
	# Any method that should be available to examples should be
	# defined in here.
  def create_fake_profile(name, values = {})
    FileUtils.mkdir_p(File.expand_path("~/.cipherstash/#{name}"))
    File.write(File.expand_path("~/.cipherstash/#{name}/profile-config.json"), default_profile.tap do |p|
      values.each do |k, v|
        nested_set(p, k, v)
      end
    end.to_json)
  end

  def with_env(vars)
    real_vals = {}

    vars.each do |var, val|
      real_vals[var] = ENV.fetch(var, :unset)
      if val == :unset
        ENV.delete(var)
      else
        ENV[var] = val
      end
    end

    yield if block_given?

    real_vals.each do |var, val|
      if val == :unset
        ENV.delete(var)
      else
        ENV[var] = val
      end
    end
  end

  private

  def default_profile
    {
      "service" => {
        "workspace" => "D3FAUL7",
        "host"      => "default.example.com",
        "port"      => 50051,
      },
      "identityProvider" => {
        "kind"     => "Auth0-Default",
        "host"     => "example-idp.example.com",
        "clientId" => "xyzzy12345",
      },
      "keyManagement" => {
        "kind"  => "AWS-KMS",
        "key"   => {
          "arn"       => "arn:aws:xx-nowhere-1:123456789012:key/abcd1234-something-funny",
          "namingKey" => "AQIBblahblahblah",
          "region"    => "xx-nowhere-1",
        },
        "awsCredentials" => {
          "kind"            => "Explicit",
          "accessKeyId"     => "ASDF4145",
          "secretAccesskey" => "s00p3rs3kr1t",
          "region"          => "xx-nowhere-1",
        },
      }
    }
  end

  def nested_set(h, k, v)
    f, r = k.split(".", 2)
    if r.nil?
      h[k] = v
    else
      h[f] ||= {}
      h[f] = nested_set(h[f], r, v)
    end
    h
  end
end
