//! secop — encrypt text or files with a passphrase so they can be sent over
//! any insecure channel (chat apps, email, ...).
//!
//! Usage:
//!   secop            paste text or an encrypted message (auto-detected)
//!   secop <file>     encrypt <file> to <file>.secop, or decrypt a .secop file

use std::fs;
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use age::secrecy::SecretString;
use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

const PREFIX: &str = "secop:";
const EXTENSION: &str = "secop";
const MIN_PASSPHRASE_LEN: usize = 8;

const HELP: &str = "\
secop - share secrets over insecure channels

USAGE:
    secop           Paste text (or an encrypted secop message), then press Ctrl-D.
                    Plain text gets encrypted, secop messages get decrypted.
    secop <file>    Encrypt <file> into <file>.secop,
                    or decrypt a .secop file back to the original.
    secop --version Print the version.

Both sides must use the same passphrase. Share it in person or over a
different channel than the one you send the message through.
";

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [] => text_mode(),
        [flag] if flag == "-h" || flag == "--help" => {
            print!("{HELP}");
            Ok(())
        }
        [flag] if flag == "-V" || flag == "--version" => {
            println!("secop {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        [path] => file_mode(Path::new(path)),
        _ => bail!("expected at most one argument\n\n{HELP}"),
    }
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
    let passphrase = loop {
        let first = rpassword::prompt_password("Passphrase: ")?;
        if first.chars().count() < MIN_PASSPHRASE_LEN {
            eprintln!("Use at least {MIN_PASSPHRASE_LEN} characters (longer is better).");
            continue;
        }
        let second = rpassword::prompt_password("Repeat passphrase: ")?;
        if first == second {
            break first;
        }
        eprintln!("Passphrases do not match, try again.");
    };
    let recipient = age::scrypt::Recipient::new(SecretString::from(passphrase));
    age::encrypt(&recipient, plaintext).context("encryption failed")
}

fn decrypt(ciphertext: &[u8]) -> Result<Vec<u8>> {
    let passphrase = rpassword::prompt_password("Passphrase: ")?;
    let identity = age::scrypt::Identity::new(SecretString::from(passphrase));
    age::decrypt(&identity, ciphertext)
        .map_err(|_| anyhow::anyhow!("wrong passphrase or corrupted message"))
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

    #[test]
    fn message_roundtrip_survives_whitespace() {
        let data = b"\x00\x01binary\xffdata".repeat(20);
        let msg = encode_message(&data);
        let mangled = format!("  {}\n {} \n", &msg[..30], &msg[30..]);
        assert_eq!(decode_message(&mangled).unwrap(), data);
    }

    #[test]
    fn age_roundtrip() {
        let pass = SecretString::from("correct horse battery".to_owned());
        let ct = age::encrypt(&age::scrypt::Recipient::new(pass.clone()), b"hi").unwrap();
        let pt = age::decrypt(&age::scrypt::Identity::new(pass), &ct).unwrap();
        assert_eq!(pt, b"hi");
    }
}
