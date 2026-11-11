# secop

Share a secret (text or a file) over an insecure channel like WhatsApp, email or Slack. Encrypt it with a passphrase or for a contact's key, paste the result anywhere, and the other side decrypts it.

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
Passphrase (leave empty to generate one):
Generated passphrase: ghost-prepare-orbit-aunt-now-upper
Send it to the recipient over a different channel than the message.
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

**Passphrases.** Leave the passphrase empty and secop generates six random words, which is far stronger than anything you'd type. If you type your own, use at least 8 characters.

**Keys, no passphrase.** For computers you send to often, like your own laptop and desktop, swap keys once:

```sh
# on each computer: print its public key (created the first time)
secop key

# on the laptop, save the desktop's key, and vice versa
secop add desktop age1...
```

From then on, `secop` asks who to encrypt for, and Enter picks the first contact. Only that computer can decrypt, with no passphrase to type. You can also read what you sent. Public keys are safe to send over WhatsApp.

Keys live in `~/.config/secop` (or `$XDG_CONFIG_HOME/secop`). `identity.txt` is this computer's secret key, readable only by you. Don't share it. `contacts.txt` is a plain list of `<name> <public key>` lines you can edit.

## Security

- Encryption is [age](https://age-encryption.org): scrypt for passphrases, X25519 for keys, ChaCha20-Poly1305 for the data. A tampered message fails to decrypt instead of decrypting to something wrong.
- **Don't send a passphrase through the same channel as the message.** Agree on it in person or over a different app.
- Anyone who copies a passphrase message can try passphrases offline. scrypt makes each guess slow, but only a strong passphrase keeps it safe. Prefer generated ones, or keys.
- The secret key file isn't passphrase-protected, much like an SSH key without a passphrase. Anyone who can read your home directory can decrypt messages sent to you.
- Text messages are the age ciphertext, base64url-encoded, behind a `secop:` prefix. Whitespace is ignored, so it's fine if a chat app wraps the line. Since it's standard age, `age -d` (with `-i ~/.config/secop/identity.txt` for key messages) can decrypt it after base64url decoding.

## License

[MIT](LICENSE)
