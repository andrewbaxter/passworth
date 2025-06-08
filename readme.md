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

Each segment must start with a `/`. So the empty path `""` has no leading slash.

You can also specify paths as JSON arrays: `["seg_1", "seg_2"]`.

## Values

Most commands default to an "unquoted" input or output. This means the input will be turned into a JSON string, and the quotes from the output will be removed if it's a JSON string. If it's not a JSON string it will be output as normal JSON.

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

At the moment this has only been built on Firefox. I'm unable to use Chrome and its ilk myself due to advertisements, but it shouldn't be hard to support.

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

        The username to use for logins. If not present, uses ACCOUNT.

      - `password`

        The password to use for logins.

      - `otp`

        An `otpauth://` string, for generating one time password tokens for the site.

# Reference

- Config (schemas)[./source/generated/jsonschema/config.schema.json]

- IPC (request)[./source/generated/jsonschema/proto.schema.json], see various responses in the same directory

# Troubleshooting access

I allow git to access ssh credentials for github. The way this works is I have git config call a shell script that calls passworth to return the key when doing network git operations.

After upgrading my system this failed. With passworth debug logging on, I saw the following logs:

```
2025-06-08T14:39:53.094203104+09:00 DEBUG: Scan process results
- meta = Pid 227468
         - uid [Some(2010)]
         - gid [Some(993)]
         - binary [Some("/nix/store/zbib0pkil5qh6dq92vzi861aa967vk56-rust-
         workspace-unknown/bin/.passworth-wrapped")]
         - first_arg_path [None]
         - tags [None]

         Pid 227466
         - uid [Some(2010)]
         - gid [Some(993)]
         - binary [Some("/nix/store/xy4jjgw87sbgwylm5kn047d9gkbhsr9x-bash-
         5.2p37/bin/bash")]
         - first_arg_path [Some("/nix/store/h9f6076x4xqn156zjd81jgi30bllnbdz-
         sshInner-ssh")]
         - tags [None]

         Pid 227465
         - uid [Some(2010)]
         - gid [Some(993)]
         - binary [Some("/nix/store/805a5wv1cyah5awij184yfad1ksmbh9f-git-2.49.0/
         libexec/git-core/git")]
         - first_arg_path [None]
         - tags [None]

         Pid 227464
         - uid [Some(2010)]
         - gid [Some(993)]
         - binary [Some("/nix/store/805a5wv1cyah5awij184yfad1ksmbh9f-git-2.49.0/
         bin/git")]
         - first_arg_path [None]
         - tags [None]

         Pid 227221
         - uid [Some(2010)]
         - gid [Some(993)]
         - binary [Some("/nix/store/vcrjkcll3rnr95xjql8rz57gjlhh2267-zsh-5.9/
         bin/zsh")]
         - first_arg_path [None]
         - tags [None]

         Pid 9406
         - uid [Some(2010)]
         - gid [Some(993)]
         - binary [Some("/nix/store/964xws8kg8n40q8yp82fgxh5cc535545-xfce4-
         terminal-1.1.5/bin/.xfce4-terminal-wrapped")]
         - first_arg_path [None]
         - tags [None]

         Pid 1945
         - uid [Some(2010)]
         - gid [Some(993)]
         - binary [Some("/nix/store/1q9lw4r2mbap8rsr8cja46nap6wvrw2p-bash-
         interactive-5.2p37/bin/bash")]
         - first_arg_path [None]
         - tags [None]

         Pid 1944
         - uid [Some(0)]
         - gid [Some(0)]
         - binary [Some("/nix/store/af291yai47szhz3miviwslzrjqky31xw-util-linux-
         2.41-bin/bin/runuser")]
         - first_arg_path [None]
         - tags [None]

         Pid 1580
         - uid [Some(0)]
         - gid [Some(0)]
         - binary [Some("/nix/store/if9z6wmzmb07j63c02mvfkhn1mw1w5p4-systemd-
         257.5/lib/systemd/systemd")]
         - first_arg_path [Some("/nix/store/allnh5k9xkmi2f6fcqq5fi1jcn46an4d-
         nixos-system-dev-25.05.803471.4792576cb003/init")]
         - tags [None]

         Pid 1565
         - uid [Some(0)]
         - gid [Some(0)]
         - binary [Some("/nix/store/if9z6wmzmb07j63c02mvfkhn1mw1w5p4-systemd-
         257.5/bin/systemd-nspawn")]
         - first_arg_path [None]
         - tags [Some({"container-dev"})]

         Pid 1
         - uid [Some(0)]
         - gid [Some(0)]
         - binary [Some("/nix/store/if9z6wmzmb07j63c02mvfkhn1mw1w5p4-systemd-
         257.5/lib/systemd/systemd")]
         - first_arg_path [None]
         - tags [None]
2025-06-08T14:39:53.094278775+09:00 DEBUG: Permit: Testing permissions for path ["device", "apricorn", "ssh"]
2025-06-08T14:39:53.094379166+09:00 DEBUG: Permit: Match user result: false
- match_ = {
             "walk_ancestors": 0,
             "user_id": 0,
             "group_id": null
           }
2025-06-08T14:39:53.094390996+09:00 DEBUG: Permit: Rule result: false
2025-06-08T14:39:53.094546757+09:00 DEBUG: Permit: Match binary result: false
- match_ = {
             "walk_ancestors": 1,
             "path": "/nix/store/1q9lw4r2mbap8rsr8cja46nap6wvrw2p-bash-
           interactive-5.2p37/bin/bash",
             "first_arg_path": "/nix/store/h9f6076x4xqn156zjd81jgi30bllnbdz-
           sshInner-ssh"
           }
2025-06-08T14:39:53.094558357+09:00 DEBUG: Permit: Rule result: false
2025-06-08T14:39:53.094702998+09:00 DEBUG: Permit: Match binary result: false
- match_ = {
             "walk_ancestors": 1,
             "path": "/nix/store/1q9lw4r2mbap8rsr8cja46nap6wvrw2p-bash-
           interactive-5.2p37/bin/bash",
             "first_arg_path": "/nix/store/kmd70favrfxy1skgnq6vl01036296q85-
           sshInner-scp"
           }
2025-06-08T14:39:53.094714588+09:00 DEBUG: Permit: Rule result: false
2025-06-08T14:39:53.094868669+09:00 DEBUG: Permit: Match binary result: false
- match_ = {
             "walk_ancestors": 1,
             "path": "/nix/store/1q9lw4r2mbap8rsr8cja46nap6wvrw2p-bash-
           interactive-5.2p37/bin/bash",
             "first_arg_path": "/nix/store/3yarh15pf7jl9swjfji3sgrcc1hbb933-
           spagh_ssh/bin/spagh"
           }
2025-06-08T14:39:53.094880299+09:00 DEBUG: Permit: Rule result: false
```

The above output provides comprehensive information about how the access check was done.

- The first section ("Scan process results") lists all of the information gathered about the identity of the requester. This is information about all processes in the process tree chain ending at the process that made the request (in this case, the passworth binary).

- After that, "Testing permissions for path" indicates what data (resource) the process was trying to access.

- Each rule that grants access to the resource is then tested sequentially until one matches, and the results printed. Rules can have a combination of clauses (user, binary, etc) and these individual results are listed before the rule's final result.

In this case I expected the 2nd rule, matching the git ssh wrapper `sshInner-ssh` to pass, but it didn't. Looking at each clause property:

- `walk_ancestors: 1` - this means that the clause applies to any process within 1 distance of the requester. From the first section, this is:

  ```
  Pid 227466
  - uid [Some(2010)]
  - gid [Some(993)]
  - binary [Some("/nix/store/xy4jjgw87sbgwylm5kn047d9gkbhsr9x-bash-5.2p37/bin/bash")]
  - first_arg_path [Some("/nix/store/h9f6076x4xqn156zjd81jgi30bllnbdz-sshInner-ssh")]
  - tags [None]
  ```

- `"path": "/nix/store/1q9lw4r2mbap8rsr8cja46nap6wvrw2p-bash-interactive-5.2p37/bin/bash"`

  Okay, this is the issue. For some reason the bash version in my container doesn't match the root system version I used when defining the rules.

- `"first_arg_path": "/nix/store/h9f6076x4xqn156zjd81jgi30bllnbdz-sshInner-ssh"`

  I could stop after finding the mismatch above, but for illustrative purposes, pretending there was no mismatch, then the clause would confirm that the first argument to bash (here, the script is translated to a bash call via the shebang line) matches the desired value.

  Luckily these do match.
