//! secop — encrypt text or files so they can be sent over any insecure channel
//! (chat apps, email, ...), either with a passphrase or to a contact's public key.

mod keys;

use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use age::secrecy::SecretString;
use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

const PREFIX: &str = "secop:";
const EXTENSION: &str = "secop";
const MIN_PASSPHRASE_LEN: usize = 8;
const GENERATED_WORDS: usize = 6;
const WORDLIST: &str = include_str!("../assets/bip39-english.txt");

const HELP: &str = "\
secop - share secrets over insecure channels

USAGE:
    secop                   Paste text (or an encrypted secop message), then press Ctrl-D.
                            Plain text gets encrypted, secop messages get decrypted.
    secop <file>            Encrypt <file> into <file>.secop,
                            or decrypt a .secop file back to the original.
    secop key               Show this computer's public key (creating it the first time).
    secop add <name> <key>  Save another computer's public key as a contact.
    secop --version         Print the version.

Passphrase: both sides type the same passphrase. Leave it empty to generate a
strong one. Share it in person or over a different channel than the message.

Keys: run `secop key` on each computer and `secop add` the other one's key.
Then you can encrypt for that contact with no passphrase, and only that
computer can decrypt. Keys live in ~/.config/secop.
";

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        [] => text_mode(),
        ["-h" | "--help"] => {
            print!("{HELP}");
            Ok(())
        }
        ["-V" | "--version"] => {
            println!("secop {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        ["key"] => show_key(),
        ["add", name, key] => add_contact(name, key),
        ["add", ..] => bail!("usage: secop add <name> <public key>"),
        [path] => file_mode(Path::new(path)),
        _ => bail!("expected at most one argument\n\n{HELP}"),
    }
}

fn show_key() -> Result<()> {
    let (identity, created) = keys::load_or_create_identity()?;
    if created {
        eprintln!(
            "Created a key for this computer in {}",
            keys::identity_path()?.display()
        );
    }
    let public = identity.to_public().to_string();
    println!("{public}");
    if io::stdout().is_terminal() && copy_to_clipboard(&public) {
        eprintln!("(copied to clipboard)");
    }
    eprintln!(
        "\nThis public key is safe to share. On the other computer, run:\n    secop add <name-for-this-computer> {public}"
    );
    Ok(())
}

fn add_contact(name: &str, key: &str) -> Result<()> {
    let replaced = keys::add_contact(name, key)?;
    let verb = if replaced { "Updated" } else { "Added" };
    eprintln!("{verb} contact `{name}`. Messages you encrypt for it can only be read there.");
    if keys::load_identity()?.is_none() {
        eprintln!("Tip: run `secop key` here too and add this computer on the other one to reply.");
    }
    Ok(())
}

fn text_mode() -> Result<()> {
    let stdin = io::stdin();
    if stdin.is_terminal() {
        eprintln!("Paste text or an encrypted message, then press Ctrl-D on an empty line:");
    }
    let mut input = Vec::new();
    stdin
        .lock()
        .read_to_end(&mut input)
        .context("reading input")?;

    let text = String::from_utf8_lossy(&input);
    if text.trim_start().starts_with(PREFIX) {
        let ciphertext = decode_message(&text)?;
        let plaintext = decrypt(&ciphertext)?;
        let mut stdout = io::stdout().lock();
        if stdout.is_terminal() {
            writeln!(stdout, "\n--- decrypted ---")?;
        }
        stdout.write_all(&plaintext)?;
        if stdout.is_terminal() && !plaintext.ends_with(b"\n") {
            writeln!(stdout)?;
        }
        return Ok(());
    }

    if input.iter().all(u8::is_ascii_whitespace) {
        bail!("nothing to encrypt");
    }
    let message = encode_message(&encrypt(&input)?);
    println!("{message}");
    if io::stdout().is_terminal() && copy_to_clipboard(&message) {
        eprintln!("(copied to clipboard)");
    }
    Ok(())
}

fn file_mode(path: &Path) -> Result<()> {
    let data = fs::read(path).with_context(|| format!("reading {}", path.display()))?;

    if path.extension().is_some_and(|ext| ext == EXTENSION) {
        let output = path.with_extension("");
        ensure_absent(&output)?;
        // Accept both the binary format and a pasted text message saved to a file.
        let ciphertext = match std::str::from_utf8(&data) {
            Ok(text) if text.trim_start().starts_with(PREFIX) => decode_message(text)?,
            _ => data,
        };
        let plaintext = decrypt(&ciphertext)?;
        fs::write(&output, plaintext).with_context(|| format!("writing {}", output.display()))?;
        eprintln!("Decrypted to {}", output.display());
    } else {
        let mut output = path.as_os_str().to_owned();
        output.push(".");
        output.push(EXTENSION);
        let output = PathBuf::from(output);
        ensure_absent(&output)?;
        let ciphertext = encrypt(&data)?;
        fs::write(&output, ciphertext).with_context(|| format!("writing {}", output.display()))?;
        eprintln!("Encrypted to {}", output.display());
    }
    Ok(())
}

fn ensure_absent(path: &Path) -> Result<()> {
    if path.exists() {
        bail!("{} already exists, not overwriting it", path.display());
    }
    Ok(())
}

fn encrypt(plaintext: &[u8]) -> Result<Vec<u8>> {
    let contacts = keys::load_contacts()?;
    let Some(contact) = choose_contact(&contacts)? else {
        let recipient = age::scrypt::Recipient::new(read_new_passphrase()?);
        return age::encrypt(&recipient, plaintext).context("encryption failed");
    };
    // Also encrypt to ourselves, so we can read what we sent.
    let me = keys::load_identity()?.map(|identity| identity.to_public());
    let recipients = std::iter::once(&contact.recipient).chain(me.as_ref());
    encrypt_to_keys(recipients, plaintext)
}

fn encrypt_to_keys<'a>(
    recipients: impl Iterator<Item = &'a age::x25519::Recipient>,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let encryptor = age::Encryptor::with_recipients(recipients.map(|r| r as &dyn age::Recipient))?;
    let mut out = Vec::new();
    let mut writer = encryptor.wrap_output(&mut out)?;
    writer.write_all(plaintext)?;
    writer.finish()?;
    Ok(out)
}

/// Asks which contact to encrypt for. `None` means use a passphrase.
fn choose_contact(contacts: &[keys::Contact]) -> Result<Option<&keys::Contact>> {
    if contacts.is_empty() {
        return Ok(None);
    }
    let tty = File::options()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .context("opening the terminal to ask who to encrypt for")?;
    let mut reader = BufReader::new(&tty);
    let mut writer = &tty;
    writeln!(writer, "Encrypt for:")?;
    for (i, contact) in contacts.iter().enumerate() {
        writeln!(writer, "  {}) {}", i + 1, contact.name)?;
    }
    writeln!(writer, "  {}) a passphrase", contacts.len() + 1)?;
    loop {
        write!(writer, "Choice [1]: ")?;
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            bail!("no choice made");
        }
        let choice = match line.trim() {
            "" => 1,
            other => other.parse().unwrap_or(0),
        };
        match choice {
            n if (1..=contacts.len()).contains(&n) => return Ok(Some(&contacts[n - 1])),
            n if n == contacts.len() + 1 => return Ok(None),
            _ => writeln!(writer, "Pick a number from the list.")?,
        }
    }
}

fn read_new_passphrase() -> Result<SecretString> {
    loop {
        let first = rpassword::prompt_password("Passphrase (leave empty to generate one): ")?;
        if first.is_empty() {
            let generated = generate_passphrase()?;
            eprintln!("Generated passphrase: {generated}");
            eprintln!("Send it to the recipient over a different channel than the message.");
            return Ok(SecretString::from(generated));
        }
        if first.chars().count() < MIN_PASSPHRASE_LEN {
            eprintln!("Use at least {MIN_PASSPHRASE_LEN} characters, or leave it empty.");
            continue;
        }
        let second = rpassword::prompt_password("Repeat passphrase: ")?;
        if first == second {
            return Ok(SecretString::from(first));
        }
        eprintln!("Passphrases do not match, try again.");
    }
}

/// Random words from the 2048-word BIP39 list: 11 bits each, 66 bits for 6 words.
fn generate_passphrase() -> Result<String> {
    let words: Vec<&str> = WORDLIST.lines().collect();
    debug_assert_eq!(words.len(), 2048);
    let mut bytes = [0u8; 2 * GENERATED_WORDS];
    getrandom::fill(&mut bytes).map_err(|err| anyhow!("no secure randomness: {err}"))?;
    let picked: Vec<&str> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        // 2048 is a power of two, so masking to 11 bits is unbiased.
        .map(|&pair| words[usize::from(u16::from_le_bytes(pair) & 0x7ff)])
        .collect();
    Ok(picked.join("-"))
}

fn decrypt(ciphertext: &[u8]) -> Result<Vec<u8>> {
    let is_passphrase = age::Decryptor::new_buffered(ciphertext)
        .map_err(|_| anyhow!("not a valid secop message (was it cut off?)"))?
        .is_scrypt();
    if is_passphrase {
        let passphrase = rpassword::prompt_password("Passphrase: ")?;
        let identity = age::scrypt::Identity::new(SecretString::from(passphrase));
        return age::decrypt(&identity, ciphertext)
            .map_err(|_| anyhow!("wrong passphrase or corrupted message"));
    }
    let identity = keys::load_identity()?.context(
        "this message was encrypted for a key, but this computer has none (run `secop key`)",
    )?;
    age::decrypt(&identity, ciphertext).map_err(|err| match err {
        age::DecryptError::NoMatchingKeys => {
            anyhow!("this message was encrypted for a different computer's key")
        }
        _ => anyhow!("corrupted message"),
    })
}

fn encode_message(ciphertext: &[u8]) -> String {
    format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(ciphertext))
}

fn decode_message(text: &str) -> Result<Vec<u8>> {
    let body = text.trim_start().strip_prefix(PREFIX).unwrap_or(text);
    // Chat apps may wrap long lines or add stray spaces; ignore all whitespace.
    let body: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    URL_SAFE_NO_PAD
        .decode(body)
        .context("message is not valid secop text (was it cut off?)")
}

/// Best-effort copy using whatever clipboard tool the system has.
fn copy_to_clipboard(text: &str) -> bool {
    const TOOLS: &[(&str, &[&str])] = &[
        ("pbcopy", &[]),
        ("wl-copy", &[]),
        ("xclip", &["-selection", "clipboard"]),
        ("xsel", &["--clipboard", "--input"]),
    ];
    TOOLS.iter().any(|(cmd, args)| {
        let Ok(mut child) = Command::new(cmd)
            .args(*args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        else {
            return false;
        };
        let wrote = child
            .stdin
            .take()
            .is_some_and(|mut stdin| stdin.write_all(text.as_bytes()).is_ok());
        child.wait().is_ok_and(|status| status.success()) && wrote
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use age::x25519::Identity;

    #[test]
    fn message_roundtrip_survives_whitespace() {
        let data = b"\x00\x01binary\xffdata".repeat(20);
        let msg = encode_message(&data);
        let mangled = format!("  {}\n {} \n", &msg[..30], &msg[30..]);
        assert_eq!(decode_message(&mangled).unwrap(), data);
    }

    #[test]
    fn passphrase_roundtrip() {
        let pass = SecretString::from("correct horse battery".to_owned());
        let ct = age::encrypt(&age::scrypt::Recipient::new(pass.clone()), b"hi").unwrap();
        let pt = age::decrypt(&age::scrypt::Identity::new(pass), &ct).unwrap();
        assert_eq!(pt, b"hi");
    }

    #[test]
    fn key_encryption_reaches_every_recipient_only() {
        let (alice, bob, eve) = (
            Identity::generate(),
            Identity::generate(),
            Identity::generate(),
        );
        let recipients = [alice.to_public(), bob.to_public()];
        let ct = encrypt_to_keys(recipients.iter(), b"secret").unwrap();
        assert_eq!(age::decrypt(&alice, &ct).unwrap(), b"secret");
        assert_eq!(age::decrypt(&bob, &ct).unwrap(), b"secret");
        assert!(matches!(
            age::decrypt(&eve, &ct),
            Err(age::DecryptError::NoMatchingKeys)
        ));
        assert!(!age::Decryptor::new_buffered(&ct[..]).unwrap().is_scrypt());
    }

    #[test]
    fn generated_passphrases_use_the_wordlist() {
        assert_eq!(WORDLIST.lines().count(), 2048);
        let words: Vec<String> = (0..50)
            .flat_map(|_| {
                let p = generate_passphrase().unwrap();
                p.split('-').map(str::to_owned).collect::<Vec<_>>()
            })
            .collect();
        assert_eq!(words.len(), 50 * GENERATED_WORDS);
        assert!(words.iter().all(|w| WORDLIST.lines().any(|l| l == w)));
        assert_ne!(
            generate_passphrase().unwrap(),
            generate_passphrase().unwrap()
        );
    }
}
