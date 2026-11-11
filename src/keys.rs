//! This computer's key pair and the public keys of known contacts, stored in
//! `$XDG_CONFIG_HOME/secop` (default `~/.config/secop`) on both Linux and macOS.
//!
//! `identity.txt` is a standard age identity file, so `age -d -i` can use it too.
//! `contacts.txt` holds one `<name> <public key>` pair per line.

use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use age::secrecy::ExposeSecret;
use age::x25519::{Identity, Recipient};
use anyhow::{Context, Result, anyhow, bail};

pub struct Contact {
    pub name: String,
    pub recipient: Recipient,
}

fn config_dir() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os("XDG_CONFIG_HOME").filter(|d| !d.is_empty()) {
        return Ok(PathBuf::from(dir).join("secop"));
    }
    let home = std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .context("HOME is not set")?;
    Ok(PathBuf::from(home).join(".config/secop"))
}

pub fn identity_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("identity.txt"))
}

pub fn contacts_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("contacts.txt"))
}

/// Reads a file, treating a missing file as `None`.
fn read_optional(path: &Path) -> Result<Option<String>> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err).with_context(|| format!("reading {}", path.display())),
    }
}

/// Writes a file that only the owner can read, inside a private config dir.
fn write_private(path: &Path, contents: &str, create_new: bool) -> Result<()> {
    if let Some(dir) = path.parent() {
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .with_context(|| format!("creating {}", dir.display()))?;
    }
    let mut options = OpenOptions::new();
    options.write(true).mode(0o600);
    if create_new {
        options.create_new(true);
    } else {
        options.create(true).truncate(true);
    }
    options
        .open(path)
        .and_then(|mut file| file.write_all(contents.as_bytes()))
        .with_context(|| format!("writing {}", path.display()))
}

/// Loads this computer's identity, if it has one.
pub fn load_identity() -> Result<Option<Identity>> {
    let path = identity_path()?;
    let Some(text) = read_optional(&path)? else {
        return Ok(None);
    };
    parse_identity(&text)
        .with_context(|| format!("reading {}", path.display()))
        .map(Some)
}

/// Loads this computer's identity, creating one if needed. Returns whether it was created.
pub fn load_or_create_identity() -> Result<(Identity, bool)> {
    if let Some(identity) = load_identity()? {
        return Ok((identity, false));
    }
    let identity = Identity::generate();
    let contents = format!(
        "# secop key for this computer. Keep this file secret.\n# public key: {}\n{}\n",
        identity.to_public(),
        identity.to_string().expose_secret()
    );
    write_private(&identity_path()?, &contents, true)?;
    Ok((identity, true))
}

fn parse_identity(text: &str) -> Result<Identity> {
    text.lines()
        .map(str::trim)
        .find(|line| line.starts_with("AGE-SECRET-KEY-"))
        .context("no secret key found")?
        .parse()
        .map_err(|err: &str| anyhow!("invalid secret key: {err}"))
}

pub fn parse_recipient(key: &str) -> Result<Recipient> {
    key.trim()
        .parse()
        .map_err(|err: &str| anyhow!("invalid public key ({err}); it should start with age1"))
}

pub fn load_contacts() -> Result<Vec<Contact>> {
    let path = contacts_path()?;
    let Some(text) = read_optional(&path)? else {
        return Ok(Vec::new());
    };
    parse_contacts(&text).with_context(|| format!("reading {}", path.display()))
}

fn parse_contacts(text: &str) -> Result<Vec<Contact>> {
    text.lines()
        .enumerate()
        .map(|(i, line)| (i + 1, line.trim()))
        .filter(|(_, line)| !line.is_empty() && !line.starts_with('#'))
        .map(|(number, line)| {
            let (name, key) = line
                .split_once(char::is_whitespace)
                .with_context(|| format!("line {number}: expected `<name> <public key>`"))?;
            let recipient = parse_recipient(key).with_context(|| format!("line {number}"))?;
            Ok(Contact {
                name: name.to_owned(),
                recipient,
            })
        })
        .collect()
}

fn render_contacts(contacts: &[Contact]) -> String {
    let mut out = String::from("# secop contacts: <name> <public key>\n");
    for contact in contacts {
        out.push_str(&format!("{} {}\n", contact.name, contact.recipient));
    }
    out
}

/// Adds or replaces a contact. Returns whether an existing contact was replaced.
pub fn add_contact(name: &str, key: &str) -> Result<bool> {
    if name.is_empty() || name.contains(char::is_whitespace) {
        bail!("the contact name must be a single word, like `laptop`");
    }
    let recipient = parse_recipient(key)?;
    let mut contacts = load_contacts()?;
    let before = contacts.len();
    contacts.retain(|contact| contact.name != name);
    let replaced = contacts.len() != before;
    contacts.push(Contact {
        name: name.to_owned(),
        recipient,
    });
    write_private(&contacts_path()?, &render_contacts(&contacts), false)?;
    Ok(replaced)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_file_roundtrip() {
        let identity = Identity::generate();
        let text = format!(
            "# comment\n# public key: {}\n{}\n",
            identity.to_public(),
            identity.to_string().expose_secret()
        );
        let parsed = parse_identity(&text).unwrap();
        assert_eq!(parsed.to_public(), identity.to_public());
    }

    #[test]
    fn contacts_roundtrip_and_errors() {
        let a = Identity::generate().to_public();
        let b = Identity::generate().to_public();
        let text = format!("# header\n\nlaptop {a}\n  desktop   {b}  \n");
        let contacts = parse_contacts(&text).unwrap();
        assert_eq!(contacts.len(), 2);
        assert_eq!(contacts[1].name, "desktop");
        assert_eq!(contacts[1].recipient, b);

        let rendered = parse_contacts(&render_contacts(&contacts)).unwrap();
        assert_eq!(rendered[0].recipient, a);

        assert!(parse_contacts("laptop").is_err());
        assert!(parse_contacts("laptop age1nope").is_err());
    }
}
