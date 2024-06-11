model_use!();

chef_json_type!(NodeJsonClass, "Chef::Node");
chef_json_type!(NodeChefType, "node");

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Node {
    pub name: Option<String>,
    #[serde(default)]
    chef_type: NodeChefType,
    #[serde(default)]
    json_class: NodeJsonClass,
    #[serde(default)]
    pub chef_environment: String,
    #[serde(default)]
    pub run_list: Vec<String>,
    #[serde(default)]
    pub normal: HashMap<String, Value>,
    #[serde(default)]
    pub automatic: HashMap<String, Value>,
    #[serde(default)]
    pub default: HashMap<String, Value>,
    #[serde(default, rename = "override")]
    pub overrides: HashMap<String, Value>,
}

model_impl!(Node);
model_list!(NodeList);
model_result!(Node, NodeResult);
