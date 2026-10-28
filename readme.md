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

A rule applies to the path(s) it lists and everything below them. `lock`/`unlock` requests are checked against the root path (`""`), so a rule that grants `lock` must list the root path to have any effect.

### What the rules can and can't promise

Rules identify the requester by looking at the requesting process and its ancestors in `/proc`: owner uid/gid, the executable path, the first argument, and tags. This is useful for routing and for preventing accidents, but it is important to understand what each clause actually proves.

- `match_user` is a real boundary: a process can't change its uid without privileges.

- `match_binary` is **not** a boundary against other code running as the same user. The check is on the path of the running executable, not on the code that's actually executing. Any process with the same uid can run the trusted binary with `LD_PRELOAD`, ptrace a child of it, or (for the browser native messaging host) simply execute the binary and feed it requests on stdin. Treat `match_binary` as a way to stop unrelated programs from accidentally touching secrets, and as a way to narrow access within an already-trusted uid; do not treat it as isolation between mutually distrusting programs that share a uid. Isolation comes from uids, user namespaces, and which containers can see the IPC socket at all.

  For the same reason, if the browser runs as the same uid as other software you don't fully trust, add a `prompt` to the browser's rule.

- `match_tag` is only as trustworthy as the user that set the tag. Tags are self-asserted: a process calls `passworth-tag` (or sends the `tag` IPC request) and names itself. The canonical use is a higher-privileged user tagging a process tree before dropping privileges, e.g. root running `passworth-tag container-dev -- systemd-nspawn ...`, and rules then matching `tag: container-dev` together with `user: root` and a `walk_ancestors` deep enough to reach the launcher. Anything already running as that user could set the same tag, so a tag never grants more than the uid does; it only distinguishes between trees started by that user. In particular, if containers run without user namespaces, root inside one container can claim another container's tag.

- When a rule has several clauses, each clause is satisfied independently by any process within its own `walk_ancestors` window; they do not have to be satisfied by the same process.

Tags are keyed by the process's pidfd inode, which requires Linux 6.9 or newer; the server refuses to start on older kernels.

# Server setup

Security precautions and assumptions:

- Make sure your swap is encrypted! Secrets will be unencrypted in memory when requested and may be written to disk.

- The GTK user interface runs in a separate helper process (see below), so the process holding secrets doesn't parse themes, fonts, input methods or compositor traffic.

- Memory is otherwise not specially protected. The server relies on the kernel zeroing pages before they're reused by another process and on encrypted swap; it does not `mlock` memory (which would pin the whole GTK process) and does not wipe buffers after use. It does mark itself non-dumpable so secrets can't end up in a core dump, and so same-uid processes can't `ptrace` it. If you run it as root, remember root can read its memory regardless.

- Passwords and recovery phrases are stretched with argon2id (64MiB, 3 passes) before use; this memory is only used transiently during unlock.

- If you use the interactive editing command, make sure your `SECURE_EDITOR` is set up to not make backups or swap files. It must be a non-terminal editor (it's run without a console). The secret is edited in a temporary file under `XDG_RUNTIME_DIR`, and the command refuses to run if that isn't set.

- Config files can contain smartcard PINs (`fixed_pin`), so keep them private.

- The IPC framing in released `glove` (up to 0.5.1) reads a peer-supplied length without a cap and may truncate large messages, which lets any local user who can reach the socket make the server allocate arbitrarily. The fix lives on the `fix-read-framed` (main) and `fix-read-framed-0.4` branches of the `glove` repository; until it's released, the workspace `Cargo.toml` expects a checkout of the `fix-read-framed-0.4` branch at `../glove` (sibling of this repository) via `[patch.crates-io]`. Once released, drop the patch entries and bump the dependency.

### Upgrading from the legacy key scheme

Earlier versions used entered passwords directly as keys and relied on sqlcipher's PBKDF2 alone. The current version derives all keys with argon2id and uses a raw sqlcipher key. On the first launch after upgrading the server detects the old scheme, asks you to unlock as before, then asks for any remaining password or recovery phrase factors that weren't used during that unlock (so they can be re-derived without changing them), and re-keys the database. Existing passwords and recovery phrases stay valid; nothing changes from the user's point of view after that.

## Architecture note: the UI helper

`passworth-server` itself has no GTK in it. Whenever it needs to show a window (unlock, credential setup, access prompts) it starts `passworth-ui`, a small GTK helper, and talks to it over stdin/stdout with a tiny JSON protocol (`source/native/src/uiproto.rs`). The helper only ever sees what the user types into it; keys are derived and the database opened in the server. A fresh helper is started for each interaction and killed afterwards.

By default the helper is found next to the server binary and inherits the server's environment (so `WAYLAND_DISPLAY`/`XDG_RUNTIME_DIR` must be set for the server). If the server runs as root and your session doesn't, set `ui.user` in the config so the helper runs as the session user instead of root talking to your compositor:

```
"ui": { "user": "me", "env": { "WAYLAND_DISPLAY": "wayland-1" } }
```

## Installation

### Nix

Importing the provided nix `import passworth/source/default.nix { pkgs = pkgs; lib = lib; }` returns a record containing:

- `package`, the native package (with `/bin/passworth-server` and `/bin/passworth`, plus the alias `pw`)

- `extensionUnpacked`, see the section below on the browser extension

- `browserModule`, same

### Manually

`source` is a cargo workspace. In `source` do `cargo build` (needs GTK 4 and gtk4-layer-shell for `passworth-ui`; use `-p passworth-native` to skip it).

This will produce binaries `passworth-server`, `passworth-ui` and `passworth` (the CLI). I recommend aliasing the latter to `pw`. `passworth-ui` must be installed next to `passworth-server` or pointed to with `ui.binary` in the config.

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

The native messaging host only forwards `meta_keys`, `read` and `derive_otp` requests, so the extension can never write or lock regardless of the rules.

Additionally, you must add the appropriate rules to your config so that the plugin is allowed to read/derive web, like:

```
[
  {
    "paths": [ "/web" ],
    "match_binary": { "path": "/path/to/native-messaging-host/binary" },
    "permit": "read"
  }
]
```

See "What the rules can and can't promise" above: this rule matches the binary path, so anything running as the same user could run that binary itself. Add `"prompt": { "description": "Browser", "remember_seconds": 300 }` if that matters in your setup.

The full installation instructions are complex and system specific, but on Nixos, `default.nix` (see above) produces `browserModule` which you can add to `imports = [];` to set up the native messaging host. To set up access rules, you can refer to the binary at `${passworth.extensionUnpacked}/native/binary`.

The popup picks a default search path from the site's registrable domain using the public suffix list. The nix build compiles in a pinned copy (`source/nixbuild/publicSuffixList.nix`; override with the `passworth.browser.publicSuffixList` option or the `publicSuffixList` argument to `browser.nix`). For manual `cargo build`s of `source/wasm`, set `PASSWORTH_PSL_PATH` to a downloaded `public_suffix_list.dat`.

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
