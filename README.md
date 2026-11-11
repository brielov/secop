# secop

Share a secret (text or a file) over an insecure channel like WhatsApp, email or Slack. You encrypt it with a passphrase, paste the result anywhere, and the other side decrypts it with the same passphrase.

## Install

```sh
brew install brielov/tap/secop
```

Prebuilt for Linux x86_64 and macOS on Apple silicon. Elsewhere: `cargo install --git https://github.com/brielov/secop`.

## Use

**Text.** Run `secop`, paste or type, then press Ctrl-D:

```console
$ secop
Paste text or an encrypted message, then press Ctrl-D on an empty line:
my bank PIN is 1234
^D
Passphrase:
Repeat passphrase:
secop:YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0-IHNjcnlwdCB...
(copied to clipboard)
```

Send that line. On the other computer, run `secop`, paste it, press Ctrl-D and enter the passphrase. secop figures out on its own whether to encrypt or decrypt.

**Files.**

```sh
secop photo.jpg          # writes photo.jpg.secop. Send it as an attachment.
secop photo.jpg.secop    # writes photo.jpg
```

Piping works too: `cat notes.txt | secop`.

## Security

- Encryption is [age](https://age-encryption.org) with a passphrase: scrypt key derivation and ChaCha20-Poly1305. A tampered message fails to decrypt instead of decrypting to something wrong.
- **Don't send the passphrase through the same channel as the message.** Agree on it in person or over a different app. Use a long passphrase. A few random words work well.
- Text messages are the age ciphertext, base64url-encoded, behind a `secop:` prefix. Whitespace is ignored, so it's fine if a chat app wraps the line.

## License

[MIT](LICENSE)
