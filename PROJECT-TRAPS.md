# Project traps

- CONSTRAINT: Never purge `<session_dir>/.session` merely because `pass-cli test`
  and a subsequent `login` fail. A transient DNS or connection outage makes
  `test` fail while `login` correctly returns `Already authenticated`; deleting
  the still-valid session then converts a network blip into a forced re-login.
  Purge only after pass-cli explicitly reports local AEAD/session-decryption
  corruption, and retain the transient-network regression test
  (`broker/src/main.rs`).
