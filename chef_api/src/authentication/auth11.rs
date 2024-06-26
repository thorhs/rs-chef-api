use crate::utils::{expand_string, squeeze_path};
use base64::{engine::general_purpose, Engine as _};
use chrono::*;
use failure::Error;
use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use itertools::Itertools;
use openssl::hash::{hash, MessageDigest};
use openssl::rsa::Padding;
use openssl::rsa::Rsa;
use std::convert::TryFrom;
use std::fmt;

pub struct Auth11 {
    #[allow(dead_code)]
    api_version: String,
    body: Option<String>,
    date: String,
    key: Vec<u8>,
    method: String,
    path: String,
    userid: String,
}

impl fmt::Debug for Auth11 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Auth11")
            .field("method", &self.method)
            .field("userid", &self.userid)
            .field("path", &self.path)
            .field("body", &self.body)
            .finish()
    }
}

impl Auth11 {
    pub fn new(
        path: &str,
        key: &[u8],
        method: &str,
        userid: &str,
        api_version: &str,
        body: Option<String>,
    ) -> Auth11 {
        let dt = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

        let userid: String = userid.into();
        let method = String::from(method).to_ascii_uppercase();

        Auth11 {
            api_version: api_version.into(),
            body,
            date: dt,
            key: key.into(),
            method,
            path: squeeze_path(path),
            userid,
        }
    }

    fn hashed_path(&self) -> Result<String, Error> {
        debug!("Path is: {:?}", self.path);
        let hash = hash(MessageDigest::sha1(), self.path.as_bytes())?;
        let hash = general_purpose::STANDARD.encode(hash);
        Ok(hash)
    }

    fn content_hash(&self) -> Result<String, Error> {
        let body = expand_string(&self.body);
        let content = hash(MessageDigest::sha1(), body.as_bytes())?;
        let content = general_purpose::STANDARD.encode(content);
        debug!("{:?}", content);
        Ok(content)
    }

    fn canonical_user_id(&self) -> Result<String, Error> {
        hash(MessageDigest::sha1(), self.userid.as_bytes())
            .and_then(|res| Ok(general_purpose::STANDARD.encode(res)))
            .map_err(|res| res.into())
    }

    fn canonical_request(&self) -> Result<String, Error> {
        let cr = format!(
            "Method:{}\nHashed Path:{}\n\
             X-Ops-Content-Hash:{}\n\
             X-Ops-Timestamp:{}\nX-Ops-UserId:{}",
            &self.method,
            self.hashed_path()?,
            self.content_hash()?,
            self.date,
            self.canonical_user_id()?
        );
        debug!("Canonical Request is: {:?}", cr);
        Ok(cr)
    }

    fn encrypted_request(&self) -> Result<String, Error> {
        let key = Rsa::private_key_from_pem(self.key.as_slice())?;

        let cr = self.canonical_request()?;
        let cr = cr.as_bytes();

        let mut hash: Vec<u8> = vec![0; key.size() as usize];
        key.private_encrypt(cr, &mut hash, Padding::PKCS1)?;
        Ok(general_purpose::STANDARD.encode(hash))
    }

    pub fn build(self, headers: &mut HeaderMap) -> Result<(), Error> {
        let hsh = self.content_hash()?;
        headers.insert("X-Ops-Content-Hash", HeaderValue::from_str(&hsh)?);

        headers.insert(
            "X-Ops-Sign",
            HeaderValue::from_str("algorithm=sha1;version=1.1")?,
        );
        headers.insert("X-Ops-Timestamp", HeaderValue::from_str(&self.date)?);
        headers.insert("X-Ops-Userid", HeaderValue::from_str(&self.userid)?);

        let enc = self.encrypted_request()?;
        let mut i = 1;
        for h in &enc.bytes().chunks(60) {
            let key = format!("X-Ops-Authorization-{}", i);
            headers.insert(
                HeaderName::try_from(key)?,
                HeaderValue::from_bytes(&h.collect::<Vec<_>>())?,
            );
            i += 1;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Auth11;
    use std::fs::File;
    use std::io::Read;

    const PATH: &str = "/organizations/clownco";
    const BODY: &str = "Spec Body";
    const USER: &str = "spec-user";
    const DT: &str = "2009-01-01T12:00:00Z";

    const PRIVATE_KEY: &str = "fixtures/spec-user.pem";

    fn get_key_data() -> Vec<u8> {
        let mut key = String::new();
        File::open(PRIVATE_KEY)
            .and_then(|mut fh| fh.read_to_string(&mut key))
            .unwrap();
        key.into_bytes()
    }

    #[test]
    fn test_canonical_user_id() {
        let auth = Auth11 {
            api_version: String::from("1"),
            body: Some(String::from(BODY)),
            date: String::from(DT),
            key: get_key_data(),
            method: String::from("POST"),
            path: String::from(PATH),
            userid: String::from(USER),
        };
        assert_eq!(
            auth.canonical_user_id().unwrap(),
            "EAF7Wv/hbAudWV5ZkwKz40Z/lO0="
        )
    }

    #[test]
    fn test_canonical_request() {
        let auth = Auth11 {
            api_version: String::from("1"),
            body: Some(String::from(BODY)),
            date: String::from(DT),
            key: get_key_data(),
            method: String::from("POST"),
            path: String::from(PATH),
            userid: String::from(USER),
        };
        assert_eq!(
            auth.canonical_request().unwrap(),
            "Method:POST\nHashed \
             Path:YtBWDn1blGGuFIuKksdwXzHU9oE=\nX-Ops-Content-Hash:\
             DFteJZPVv6WKdQmMqZUQUumUyRs=\nX-Ops-Timestamp:2009-01-01T12:00:\
             00Z\nX-Ops-UserId:EAF7Wv/hbAudWV5ZkwKz40Z/lO0="
        )
    }

    #[test]
    fn test_private_key() {
        let auth = Auth11 {
            api_version: String::from("1"),
            body: Some(String::from(BODY)),
            date: String::from(DT),
            key: get_key_data(),
            method: String::from("POST"),
            path: String::from(PATH),
            userid: String::from(USER),
        };
        assert_eq!(
            &auth.encrypted_request().unwrap(),
            "UfZD9dRz6rFu6LbP5Mo1oNHcWYxpNIcUfFCffJS1FQa0GtfU/vkt3/O5HuCM\
             1wIFl/U0f5faH9EWpXWY5NwKR031Myxcabw4t4ZLO69CIh/3qx1XnjcZvt2w\
             c2R9bx/43IWA/r8w8Q6decuu0f6ZlNheJeJhaYPI8piX/aH+uHBH8zTACZu8\
             vMnl5MF3/OIlsZc8cemq6eKYstp8a8KYq9OmkB5IXIX6qVMJHA6fRvQEB/7j\
             281Q7oI/O+lE8AmVyBbwruPb7Mp6s4839eYiOdjbDwFjYtbS3XgAjrHlaD7W\
             FDlbAG7H8Dmvo+wBxmtNkszhzbBnEYtuwQqT8nM/8A=="
        )
    }
}
