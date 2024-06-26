//! A Chef Client API library
//!
//! This library implements the raw requests and authentication methods
//! necessary to interact with a [Chef] Server.
//!
//! See the [Chef Server API] documentation for further information on the possible requests.
//!
//! ## Connecting
//!
//! You'll need a credentials file as documented in [RFC
//! 99].
//!
//! To retrieve a list of cookbook names, first create an `ApiClient` and then make a
//! request to the cookbook endpoint:
//!
//! ```rust,no_run
//! use chef_api::api_client::{ApiClient, Execute};
//!
//! let client = ApiClient::from_credentials(None).unwrap();
//! let cookbooks = client.cookbooks().get();
//! ```
//!
//! This crate uses [`serde`] to serialize requests from JSON.
//!
//! [Chef]: https://www.chef.io/chef/
//! [Chef Server API]: https://chef-server-api-docs.chef.io/
//! [RFC 99]: https://chef.github.io/chef-rfc/rfc099-authentication-config-file.html
//! [`serde`]: https://serde.rs/
//!

#[macro_use]
extern crate failure;

extern crate chrono;
extern crate openssl;
extern crate url;

extern crate futures;

extern crate hyper;
extern crate hyper_openssl;
extern crate tokio;

#[macro_use]
extern crate log;

extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;

extern crate toml;

extern crate dirs;

pub use crate::errors::*;
pub mod authentication;
pub mod errors;
#[macro_use]
mod macros;
pub mod credentials;
pub mod utils;

pub mod api_client;

pub use crate::requests::*;
pub mod requests;
