This is a Ruby (with Rust backend) client for the [CipherStash encrypted, searchable data store](https://cipherstash.com).

> # !!! CURRENT STATUS !!!
>
> This client is currently extremely experimental and incomplete.
> While we're happy for you to use it, please don't expect everything to work perfectly, nor for all features of other CipherStash clients to be available.
>
> At present, the following things should work:
>
> * Nothing.


# Installation

## Pre-requisites

### Rust

To build the dependencies of `cipherstash-client`, you must have at least Rust 1.59 installed.
If you are on an arm64 machine (M1 Mac, for example) you will need to be running a recent Rust nightly.
We'll have better docs on how to do that in the future; for now, if you don't know how to do that, this gem *probably* isn't for you just yet.


### AWS Encryption SDK

In lieu of building Ruby bindings for the AWS Encryption SDK, we instead use the AWS Encryption CLI.
This is a Python program, which is most easily installed using `pip`:

```
pip install aws-encryption-sdk-cli
```


## Da gem!  Da gem!

So, if that's all good, you can install it as a gem:

    gem install cipherstash-client

There's also the wonders of [the Gemfile](http://bundler.io):

    gem 'cipherstash-client'

If you're the sturdy type that likes to run from git:

    rake install

Or, if you've eschewed the convenience of Rubygems entirely, then you
presumably know what to do already.


# Usage

## Getting Off The Ground

First off, you need to load the library and a client:

```ruby
require "cipherstash/client"

stash = CipherStash::Client.new
```

This will pick up your configuration from the default profile; if you want to specify a different profile to load:

```ruby
stash = CipherStash::Client.new(profileName: "bob")
```

Alternately, you can also set all configuration via environment variables.
See [the CipherStash Client Configuration reference](https://docs.cipherstash.com/reference/client-configuration.html) for more details.


## Collections

All data in CipherStash is stored in [collections](https://docs.cipherstash.com/reference/glossary.html#collection).
You can load all collections:


```ruby
stash.collections  # => [<collection>, <collection>, ...]
```

Or you can load a single collection, if you know its name:

```ruby
collection = stash.collection("movies")
```


## Inserting Records

To insert a [record](https://docs.cipherstash.com/reference/glossary.html#record):

```ruby
collection.insert({ foo: "bar", baz: "wombat" })
```


## Querying

A query is a set of constraints applied to the records in a collection.
Constraints are defined in a block passed to `Collection#query`, like so:

```ruby
collection.query do |movies|
  movies.exactTitle("Star Trek: The Motion Picture")
  movies.year.gt(1990.0)
end
```

Multiple constraints will be `AND`ed together, and so the above query will not return any records because "Star Trek: The Motion Picture" was made before 1990.


## API Documentation

The [auto-generated API documentation](https://rubydoc.info/gems/cipherstash-client) should provide complete documentation of all public methods and classes.



# Contributing

Please see [CONTRIBUTING.md](CONTRIBUTING.md).


