This is a Ruby (with Rust backend) client for the [CipherStash encrypted, searchable data store](https://cipherstash.com).

> # !!! CURRENT STATUS !!!
>
> This client is currently in a "late-alpha" state.
> While we're happy for you to use it, and most things work, there are a couple of things missing.
> If something *not* on the list below is broken for you, please [report an issue](https://github.com/cipherstash/ruby-client/issues).
>
> At present, interacting with collections or records created with StashJS is not supported.


# Installation

As `cipherstash-client` uses Rust-based libraries (`ore-rs` and `enveloperb`) for its underlying cryptography, installation can be a bit trickier than for most gems.

We provide pre-built native gems, which contain the underlying cryptographic primitive code pre-compiled, for platforms we officially support.
Those platforms are:

* Linux `x86_64` and `aarch64` ("arm64"); and
* macOS `x86_64` and `arm64`


## Pre-requisites

### Rust

For platforms we don't (yet) officially support, you will need to have at least Rust 1.59.0 installed.
If you are on an arm64 machine (M1 Mac, for example) you will need to be running a recent Rust nightly for SIMD intrinsics support.


## Da gem!  Da gem!

Once the above pre-requisites are all sorted, you can go ahead and install `cipherstash-client` itself.

The basic option is to install it as a gem directly:

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


# Need help?

Head over to our [support forum](https://discuss.cipherstash.com/), and we'll get back to you super quick! 


# Contributing

Please see [CONTRIBUTING.md](CONTRIBUTING.md) for general contribution guidelines.


## Making a Release

If you have push access to the GitHub repository, you can make a release by doing the following:

1. Run `git version-bump -n <major|minor|patch>` (see [the semver spec](https://semver.org) for what each of major, minor, and patch version bumps represent).

2. Write a changelog for the release, in Git commit style (headline on the first line, blank line, then Markdown text as you see fit).
   Save/exit your editor.
   This will automatically push the newly-created annotated tag, which will in turn kick off a release build of the gem and push it to [RubyGems.org](https://rubygems.org/gem/cipherstash-client).

3. Run `rake release` to automagically create a new [GitHub release](https://github.com/cipherstash/ruby-client/releases) for the project.

... and that's it!


# Licence

Unless otherwise stated, everything in this repo is covered by the following
copyright notice:

    Copyright (C) 2022  CipherStash Inc.

    This program is free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License version 3, as
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
