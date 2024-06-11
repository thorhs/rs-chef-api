extern crate chef;
extern crate chef_api;

extern crate env_logger;
use log::{self, error};

use serde::Deserialize;
extern crate serde_json;

use std::collections::HashMap;

use chef::models::*;
use chef_api::api_client::*;
use log::info;

pub fn main() {
    env_logger::init();
    let client = ApiClient::from_credentials(None).unwrap();

    let mut fields: HashMap<&str, Vec<&str>> = HashMap::new();
    fields.insert("name", vec!["name"]);
    fields.insert("ipaddress", vec!["ipaddress"]);
    fields.insert("ip6address", vec!["ip6address"]);
    fields.insert("chef_environment", vec!["chef_environment"]);
    fields.insert("network", vec!["network"]);

    println!("Starting search");
    let n = client
        .search()
        .search_index("node")
        .q("role:rb_vault_server")
        .post(&fields)
        // .get()
        .unwrap();
    println!("Done searching");

    // let nr: NodeResult = n.into();
    let nr: PartialResultResult = n.into();
    for n in nr {
        info!("{:?}", n);
        /* println!(
            "{}: {}",
            n.data.get("name").unwrap(),
            n.data.get("ipaddress").unwrap()
        ); */
        let network: Network =
            serde_json::from_value(n.data.get("network").unwrap().clone()).unwrap();
        println!("{:?}", network);
        println!("{:?}", get_addresses(&network, Some("inet6")));
    }
}

fn get_addresses(network: &Network, family: Option<&str>) -> Vec<String> {
    let mut result = Vec::new();
    for (_interface_name, interface) in network.interfaces.iter() {
        for (address, addr_info) in interface.addresses.iter() {
            if (family.is_some() && addr_info.family == family.unwrap())
                || (family.is_none() && addr_info.family.starts_with("inet"))
            {
                match addr_info.scope.as_str() {
                    "Global" => result.push(address.clone()),
                    "Node" => (), // Loopback etc
                    "Link" => (), // non-routable
                    _ => error!("Address scope '{}' unknown", addr_info.scope),
                };
            }
        }
    }

    result
}

#[derive(Deserialize, Debug, Clone, Default)]
pub struct Network {
    pub interfaces: HashMap<String, Interface>,
    #[serde(default)]
    pub default_gateway: String,
    #[serde(default)]
    pub default_interface: String,
}

#[derive(Deserialize, Debug, Clone, Default)]
pub struct Interface {
    #[serde(default)]
    pub addresses: HashMap<String, AddressInfo>,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub routes: Vec<Route>,
}

#[derive(Deserialize, Debug, Clone, Default)]
pub struct AddressInfo {
    #[serde(default)]
    pub family: String,
    #[serde(default)]
    pub prefixlen: String,
    #[serde(default)]
    pub netmask: String,
    #[serde(default)]
    pub scope: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Deserialize, Debug, Clone, Default)]
pub struct Route {
    #[serde(default)]
    pub destination: String,
    #[serde(default)]
    pub family: String,
    #[serde(default)]
    pub via: String,
    #[serde(default)]
    pub metric: String,
    #[serde(default)]
    pub proto: String,
    #[serde(default)]
    pub scope: String,
    #[serde(default)]
    pub src: String,
}
