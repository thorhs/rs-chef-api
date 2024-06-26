use hyper;
use openssl;
use serde_json;
use std;
use toml;
use url;

#[derive(Fail, Debug)]
pub enum ChefError {
    // errrors coming from somewhere else
    #[fail(display = "An error occurred attempting to sign the request: {}", _0)]
    OpenSSLError(#[cause] openssl::error::ErrorStack),
    #[fail(display = "An error occurred attempting to open a file: {}", _0)]
    IOError(#[cause] std::io::Error),
    #[fail(display = "An error occurred attempting to handle JSON: {}", _0)]
    JsonError(#[cause] serde_json::Error),
    #[fail(
        display = "An error occurred attempting to parse the Chef Server URL: {}",
        _0
    )]
    UrlParseError(#[cause] url::ParseError),
    #[fail(
        display = "An error occurred attempting to parse the Chef Server URL: {}",
        _0
    )]
    UriError(#[cause] hyper::Error),
    #[fail(display = "An error occurred communicating to the Chef Server: {}", _0)]
    HTTPError(#[cause] hyper::Error),
    #[fail(display = "An error occurred when using the API client: {}", _0)]
    BorrowError(#[cause] std::cell::BorrowMutError),
    #[fail(display = "Failed to parse credentials file: {}", _0)]
    TomlDeserializeError(#[cause] toml::de::Error),

    // internal errors
    #[fail(display = "Failed to read private key at {}", _0)]
    PrivateKeyError(String),
    #[fail(display = "Failed to interpret a list of items")]
    ListError,
    #[fail(display = "Failed to fetch {} from JSON", _0)]
    KeyMissingError(String),
    #[fail(display = "Can't read config file at {}", _0)]
    UnparseableConfigError(String),
    #[fail(display = "Chef Server returned an error, with error code: {}", _0)]
    ChefServerResponseError(u16),
    #[fail(display = "Failed to deserialize JSON")]
    DeserializeError,
    #[fail(
        display = "Both client_name and node_name are set in the {} profile",
        _0
    )]
    DuplicateClientNameError(String),
}
