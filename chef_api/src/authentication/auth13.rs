use crate::utils::{expand_string, squeeze_path};
use base64::{engine::general_purpose, Engine as _};
use chrono::*;
use failure::Error;
use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use itertools::Itertools;
use openssl::hash::{hash, MessageDigest};
use openssl::pkey::PKey;
use openssl::sign::Signer;
use std::convert::TryFrom;
use std::fmt;

pub struct Auth13 {
    api_version: String,
    body: Option<String>,
    date: String,
    key: Vec<u8>,
    method: String,
    path: String,
    userid: String,
}

impl fmt::Debug for Auth13 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Auth13")
            .field("method", &self.method)
            .field("userid", &self.userid)
            .field("path", &self.path)
            .field("body", &self.body)
            .finish()
    }
}

impl Auth13 {
    pub fn new(
        path: &str,
        key: &[u8],
        method: &str,
        userid: &str,
        api_version: &str,
        body: Option<String>,
    ) -> Auth13 {
        let dt = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

        let userid: String = userid.into();
        let method = String::from(method).to_ascii_uppercase();

        Auth13 {
            api_version: api_version.into(),
            body,
            date: dt,
            key: key.into(),
            method,
            path: squeeze_path(path),
            userid,
        }
    }

    fn content_hash(&self) -> Result<String, Error> {
        let body = expand_string(&self.body);
        debug!("Content body is: {:?}", body);
        let content = hash(MessageDigest::sha256(), body.as_bytes())?;
        let content = general_purpose::STANDARD.encode(content);
        debug!("Content hash is: {:?}", content);
        Ok(content)
    }

    fn canonical_request(&self) -> Result<String, Error> {
        let cr = format!(
            "Method:{}\nPath:{}\nX-Ops-Content-Hash:{}\n\
             X-Ops-Sign:version=1.3\nX-Ops-Timestamp:{}\n\
             X-Ops-UserId:{}\nX-Ops-Server-API-Version:{}",
            &self.method,
            &self.path,
            self.content_hash()?,
            self.date,
            &self.userid,
            &self.api_version
        );
        debug!("Canonical Request is: {:?}", cr);
        Ok(cr)
    }

    fn signed_request(&self) -> Result<String, Error> {
        let key = PKey::private_key_from_pem(self.key.as_slice())?;

        let cr = self.canonical_request()?;
        let cr = cr.as_bytes();

        let mut signer = Signer::new(MessageDigest::sha256(), &key)?;
        signer.update(cr).unwrap();
        let result = signer.sign_to_vec()?;
        let result = general_purpose::STANDARD.encode(result);
        debug!("base64 encoded result is {:?}", result);
        Ok(result)
    }

    pub fn build(self, headers: &mut HeaderMap) -> Result<(), Error> {
        let hsh = self.content_hash()?;

        headers.insert("X-Ops-Content-Hash", HeaderValue::from_str(&hsh)?);
        headers.insert(
            "X-Ops-Sign",
            HeaderValue::from_str("algorithm=sha256;version=1.3")?,
        );
        headers.insert("X-Ops-Timestamp", HeaderValue::from_str(&self.date)?);
        headers.insert("X-Ops-Userid", HeaderValue::from_str(&self.userid)?);

        let enc = self.signed_request()?;
        let mut i = 1;
        for h in &enc.bytes().chunks(60) {
            let key = format!("X-Ops-Authorization-{}", i);
            let value = h.collect::<Vec<_>>();
            let value = HeaderValue::from_bytes(&value)?;
            headers.insert(HeaderName::try_from(key)?, value);
            i += 1;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Auth13;

    use base64::{engine::general_purpose, Engine as _};
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::sign::Verifier;
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
    fn test_canonical_request() {
        let auth = Auth13 {
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
            "Method:POST\nPath:/organizations/clownco\nX-Ops-Content-Hash:\
             hDlKNZhIhgso3Fs0S0pZwJ0xyBWtR1RBaeHs1DrzOho=\nX-Ops-Sign:version=1.\
             3\nX-Ops-Timestamp:2009-01-01T12:00:00Z\nX-Ops-UserId:\
             spec-user\nX-Ops-Server-API-Version:1"
        )
    }

    #[test]
    fn test_signed_request() {
        let auth = Auth13 {
            api_version: String::from("1"),
            body: Some(String::from(BODY)),
            date: String::from(DT),
            key: get_key_data(),
            method: String::from("POST"),
            path: String::from(PATH),
            userid: String::from(USER),
        };
        let sig = &auth.signed_request().unwrap();
        let req = &auth.canonical_request().unwrap();

        let sig_raw = general_purpose::STANDARD.decode(&sig).unwrap();
        let mut key: Vec<u8> = vec![];
        let mut fh = File::open(PRIVATE_KEY).unwrap();
        fh.read_to_end(&mut key).unwrap();
        let key = PKey::private_key_from_pem(key.as_slice()).unwrap();

        let mut ver = Verifier::new(MessageDigest::sha256(), &key).unwrap();
        ver.update(req.as_bytes()).unwrap();
        assert!(ver.verify(sig_raw.as_slice()).unwrap());

        assert_eq!(
            sig,
            "FZOmXAyOBAZQV/uw188iBljBJXOm+m8xQ/8KTGLkgGwZNcRFxk1m953XjE3W\
             VGy1dFT76KeaNWmPCNtDmprfH2na5UZFtfLIKrPv7xm80V+lzEzTd9WBwsfP\
             42dZ9N+V9I5SVfcL/lWrrlpdybfceJC5jOcP5tzfJXWUITwb6Z3Erg3DU3Uh\
             H9h9E0qWlYGqmiNCVrBnpe6Si1gU/Jl+rXlRSNbLJ4GlArAPuL976iTYJTzE\
             MmbLUIm3JRYi00Yb01IUCCKdI90vUq1HHNtlTEu93YZfQaJwRxXlGkCNwIJe\
             fy49QzaCIEu1XiOx5Jn+4GmkrZch/RrK9VzQWXgs+w=="
        )
    }
}
