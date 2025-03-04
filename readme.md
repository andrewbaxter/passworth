A butler for your secrets.

Requires Linux.

Features:

- All secrets are JSON, stored in encrypted sqlite3

- A read-only browser plugin, no passwords ever reach your clipboard

- Use on the command line, in scripts

- Managed by a central process via IPC

- Grant permissions to specific commands, users, or containers based on requester metadata

- Use a variety of auth factors, such as passwords, PIN, GPG smartcards, and recovery phrases

- Derive OTP codes, SSH public keys, GPG signatures and encryption without giving access to the private key itself

# Conventions

## Json/secret paths

Most commands need paths to operate on. The paths have the format `/seg_1/seg_2` which would refer to `X` in `{"seg_1": {"seg_2": X}}`.

Each segment must start with a `/`.  So the empty path `""` has no leading slash.

You can also specify paths as JSON arrays: `["seg_1", "seg_2"]`.

## Values

Most commands default to an "unquoted" input or output.  This means the input will be turned into a JSON string, and the quotes from the output will be removed if it's a JSON string. If it's not a JSON string it will be output as normal JSON.

If you want to input JSON or want verbatim JSON output, specify the appropriate command.

## Permissions

There are several permission levels:

- lock
- meta
- derive
- read
- write

Details are available in the config schema. Levels are tiered, so `write` permits all actions `read` can do plus more, `read` `derive`, etc.

All IPC requests and command line subcommands are named to reflect which permission is required.

# Server setup

Security precautions:

- Make sure your swap is encrypted! Secrets will be unencrypted in memory when requested and may be written to disk.

- If you use the interactive editing command, make sure your `SECRET_EDITOR` is set up to not make backups, swap files

## Installation

### Nix

Importing the provided nix `import passworth/source/default.nix { pkgs = pkgs; lib = lib; }` returns a record containing:

- `package`, the native package (with `/bin/passworth-server` and `/bin/passworth`, plus the alias `pw`)

- `extensionUnpacked`, see the section below on the browser extension

- `browserModule`, same

### Manually

In `source/native` do `cargo build`.

This will produce binaries `passworth-server` and `passworth` (the CLI). I recommend aliasing the latter to `pw`.

## Configuration

TODO

## Troubleshooting access

If you run in verbose mode, detailed access scan results and decisions will be logged.

# Client

The CLI client is `pw`.

Here is the most basic operation:

- Create secrets

  ```
  $ pw write /my/secret
  hunter2^D^D
  $
  ```
  or
  ```
  $ pw write --json /my/secret
  "hunter2"^D^D
  ```

- Read secrets

  ```
  $ pw read /my/secret
  ```

# Browser extension

TODO screenshots

Automatically fill in username/password by clicking the icon or pressing `Ctrl+Shift+L`. Fill in the last focused text box by clicking the icons for any other secret field.

At the moment this has only been built on Firefox.  I'm unable to use Chrome and its ilk myself due to advertisements, but it shouldn't be hard to support.

The browser plugin is a native plugin - this means there's two components, the extension (a normal extension) and the "native messaging host", a native binary that must be registered with the browser so the extension can communicate with it.

Additionally, you must add the appropriate rules to your config so that the plugin is allowed to read/derive web, like:

```
[
  {
    "paths": [ "/web" ],
    "match_binary": { path": "/path/to/native-messaging-host/binary" },
    "permit": "read"
  }
]
```

The full installation instructions are complex and system specific, but on Nixos, `default.nix` (see above) produces `browserModule` which you can add to `imports = [];` to set up the native messaging host. To set up access rules, you can refer to the binary at `${passworth.extensionUnpacked}/native/binary`.

In the same directory, `packageExt.nix` will build the extension `.zip` file: `nix-build package_ext.nix -o /mnt/downloads/ext_firefox.zip`

# Recommended schema

Some builtin tools assume this schema for default searches, behaviors, etc.

- `web/`

  - DOMAIN or SUBDOMAIN

    - ACCOUNT 

      This can be an arbitrary descriptive string if a `user` field is provided, otherwise it will be used as the username for logins.

      - `user`

        The username to use for logins.  If not present, uses ACCOUNT.

      - `password`

        The password to use for logins.

      - `otp`
    
        An `otpauth://` string, for generating one time password tokens for the site.

# Reference

- Config (schemas)[./source/generated/jsonschema/config.schema.json]

- IPC (request)[./source/generated/jsonschema/proto.schema.json], see various responses in the same directory