macro_rules! build {
    ($name:ident, $type:ident) => {
        #[doc = "Generate a new $type request."]
        pub fn $name(&self) -> $type {
            self.into()
        }
    };
}

macro_rules! import {
    () => {
        use failure::Error;
        use $crate::api_client::*;
        use $crate::authentication::auth11::Auth11;
        use $crate::authentication::auth13::Auth13;
        use $crate::credentials::Config;
        use $crate::utils::add_path_element;

        use serde::Serialize;
        use serde_json;

        use std::rc::Rc;

        use tokio::runtime::Runtime;

        use hyper::client::HttpConnector;
        use hyper::header::{self, HeaderValue};
        use hyper::Client as HyperClient;
        use hyper::{Method, Request};
        use hyper_tls::HttpsConnector;
    };
}

macro_rules! path {
    (
        $(#[$outer:meta])*
        -> $n:ident = $txt:tt
    ) => {
        $(#[$outer])*
        pub fn $n(&mut self) -> &mut Self {
            self.path = add_path_element(self.path.clone(), $txt);
            self
        }
    };
    (
        $(#[$outer:meta])*
        -> $n:ident
    ) => {
        $(#[$outer])*
        pub fn $n(&mut self) -> &mut Self {
            self.path = add_path_element(self.path.clone(), stringify!($n));
            self
        }
    };
    (
        $(#[$outer:meta])*
        $n:ident
    ) => {
        $(#[$outer])*
        pub fn $n(&mut self, value: &str) -> &mut Self {
            self.path = add_path_element(self.path.clone(), value);
            self
        }

    };
}

macro_rules! acls {
    () => {
        /// Get the list of ACLs on this object
        pub fn acl(&mut self) -> &mut Self {
            self.path = add_path_element(self.path.clone(), "_acl");
            self
        }

        /// Modify the given permission on the object.
        pub fn permission(&mut self, permission: &str) -> &mut Self {
            self.path = add_path_element(self.path.clone(), permission);
            self
        }
    };
}

macro_rules! request_type {
    ($n:ident) => {
        #[derive(Debug, Clone)]
        pub struct $n<'c> {
            pub(crate) client: &'c Rc<HyperClient<HttpsConnector<HttpConnector>>>,
            pub(crate) config: &'c Config,
            pub(crate) path: String,
            pub(crate) api_version: String,
            pub(crate) q: Option<String>,
        }
    };
}

macro_rules! requests {
    (root $n:ident) => {
        request_type!($n);

        impl<'c> From<&'c ApiClient> for $n<'c> {
            fn from(api: &'c ApiClient) -> Self {
                let path = String::from("/");
                Self {
                    config: &api.config,
                    client: &api.client,
                    path,
                    api_version: String::from("1"),
                    q: None,
                }
            }
        }

        execute!($n);
    };
    (root $n:ident, $p:tt) => {
        request_type!($n);

        impl<'c> From<&'c ApiClient> for $n<'c> {
            fn from(api: &'c ApiClient) -> Self {
                let path = add_path_element(String::from("/"), stringify!($p));
                Self {
                    config: &api.config,
                    client: &api.client,
                    path,
                    api_version: String::from("1"),
                    q: None,
                }
            }
        }

        execute!($n);
    };
    ($n:ident, $p:tt) => {
        request_type!($n);

        impl<'c> From<&'c ApiClient> for $n<'c> {
            fn from(api: &'c ApiClient) -> Self {
                let path =
                    add_path_element(api.config.organization_path().unwrap(), stringify!($p));
                Self {
                    config: &api.config,
                    client: &api.client,
                    path,
                    api_version: String::from("1"),
                    q: None,
                }
            }
        }

        execute!($n);
    };
}

macro_rules! execute {
    ($n:ident) => {
        use serde_json::Value;
        use $crate::errors::ChefError;

        impl<'e> Execute for $n<'e> {
            fn api_version(&mut self, api_version: &str) -> &mut Self {
                self.api_version = api_version.into();
                self
            }

            #[doc(hidden)]
            fn execute<B>(&self, body: Option<B>, method: &str) -> Result<Value, Error>
            where
                B: Serialize,
            {
                let userid = self.config.client_name()?;
                let key = self.config.key()?;
                let sign_ver = self.config.sign_ver.clone();
                let path = self.path.clone();
                let api_version = self.api_version.clone();

                let mut url = url::Url::parse(&format!("{}{}", &self.config.url_base()?, path))?; //.parse()?;
                if self.q.is_some() {
                    url.query_pairs_mut()
                        .append_pair("q", self.q.as_ref().unwrap());
                }

                let mth = match method {
                    "put" => Method::PUT,
                    "post" => Method::POST,
                    "delete" => Method::DELETE,
                    "head" => Method::HEAD,
                    _ => Method::GET,
                };

                let mut req_builder = Request::builder().method(mth).uri(url.as_str());

                let body = match body {
                    Some(b) => serde_json::to_string(&b)?,
                    None => serde_json::to_string("")?,
                };

                match sign_ver.as_str() {
                    "1.1" => Auth11::new(
                        &path,
                        &key,
                        method,
                        &userid,
                        &api_version,
                        Some(body.clone().into()),
                    )
                    .build(req_builder.headers_mut().unwrap())?,
                    _ => Auth13::new(
                        &path,
                        &key,
                        method,
                        &userid,
                        &api_version,
                        Some(body.clone().into()),
                    )
                    .build(req_builder.headers_mut().unwrap())?,
                };

                req_builder.headers_mut().map(|h| {
                    h.insert(
                        header::ACCEPT,
                        HeaderValue::from_str("application/json").unwrap(),
                    );
                    h.insert(
                        header::CONTENT_TYPE,
                        HeaderValue::from_str("application/json").unwrap(),
                    );
                    h.insert(
                        header::CONTENT_LENGTH,
                        HeaderValue::from(body.clone().len() as u64),
                    );
                    h.insert("X-Ops-Server-API-Info", HeaderValue::from(1 as u64));
                    h.insert("X-Ops-Server-API-Version", HeaderValue::from(1 as u64));
                    h.insert("X-Chef-Version", HeaderValue::from_str("13.3.34").unwrap());
                });

                let request = req_builder.body(body.into())?;

                let client = self.client;
                let resp = async {
                    let res = client
                        .request(request)
                        .await
                        .map_err(ChefError::HTTPError)?;
                    debug!("Status is {:?}", res.status());

                    let status = res.status();
                    let body = hyper::body::to_bytes(res.into_body())
                        .await
                        .map_err(ChefError::HTTPError)?;

                    trace!("{}", String::from_utf8_lossy(&body));

                    let body: Value =
                        serde_json::from_slice(&body).map_err(ChefError::JsonError)?;

                    if status.is_success() {
                        Ok(body)
                    } else {
                        Err(ChefError::ChefServerResponseError(status.as_u16()))
                    }
                };

                let rt = Runtime::new()?;
                rt.block_on(resp).map_err(|e| e.into())
            }
        }
    };
}
