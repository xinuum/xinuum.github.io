# Release commit verification

The public key in `allowed_signers` verifies locally generated website artifact
commits created by `xinuum`. It contains no private credential.

GitHub separately verifies the same signing key. The Pages deployment job does
not create or impersonate a human Git commit.
