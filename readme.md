This is a secret butler!

Features:

- Managed by a central process via IPC, for use in containers, etc.

- Grant permissions to specific commands and users based on the secret requester PID

- Use a variety of auth factors, such as passwords, PIN, GPG smartcards, and recovery phrases

- All secrets are JSON

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

