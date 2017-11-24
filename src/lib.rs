#![cfg_attr(feature = "dev", allow(unstable_features))]
#![cfg_attr(feature = "dev", feature(plugin))]
#![cfg_attr(feature = "dev", plugin(clippy))]
// #![deny(missing_docs,
//         missing_debug_implementations, missing_copy_implementations,
//         trivial_casts, trivial_numeric_casts,
//         unsafe_code,
//         unstable_features,
//         unused_import_braces, unused_qualifications)]
#![recursion_limit = "1024"]

extern crate chrono;

extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;

extern crate chef_api;

pub mod requests;
