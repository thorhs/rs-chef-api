model_use!();

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct PartialResult {
    pub url: String,
    pub data: Value,
}

model_impl!(PartialResult);
model_list!(PartialResultList);
model_result!(PartialResult, PartialResultResult);
