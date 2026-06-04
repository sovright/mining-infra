use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

fn null_value() -> Value {
    Value::Null
}

fn empty_array_value() -> Value {
    Value::Array(Vec::new())
}

#[derive(Debug, Clone, Deserialize)]
pub struct JsonRpcRequest {
    #[serde(default = "null_value")]
    pub id: Value,
    pub method: String,
    #[serde(default = "empty_array_value")]
    pub params: Value,
}

impl JsonRpcRequest {
    pub fn params_as_array(&self) -> Result<&[Value], String> {
        self.params
            .as_array()
            .map(Vec::as_slice)
            .ok_or_else(|| "params must be a JSON array".to_string())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcErrorObject {
    pub code: i64,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct Subscribe {
    pub user_agent: Option<String>,
    pub session_id: Option<String>,
    pub host: Option<String>,
    pub port: Option<u16>,
}

#[derive(Debug, Clone)]
pub struct Authorize {
    pub worker_name: String,
    pub password: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ExtranonceSubscribe;

#[derive(Debug, Clone)]
pub struct Submit {
    pub worker_name: String,
    pub job_id: String,
    pub time_hex: String,
    pub nonce_2_hex: String,
    pub solution_hex: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Notification<T>
where
    T: Serialize,
{
    pub id: Value,
    pub method: &'static str,
    pub params: T,
}

impl<T> Notification<T>
where
    T: Serialize,
{
    pub fn new(method: &'static str, params: T) -> Self {
        Self {
            id: Value::Null,
            method,
            params,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Subscription(pub &'static str, pub String);

#[derive(Debug, Clone, Serialize)]
pub struct SubscribeResult(pub Subscription, pub String);

#[derive(Debug, Clone, Serialize)]
pub struct NotifyParams(
    pub String,
    pub String,
    pub String,
    pub String,
    pub String,
    pub String,
    pub String,
    pub bool,
);

#[derive(Debug, Clone, Serialize)]
pub struct SetTargetParams(pub String);

#[derive(Debug, Clone, Serialize)]
pub struct SetDifficultyParams(pub f64);

#[derive(Debug, Clone, Serialize)]
pub struct SetExtranonceParams(pub String, pub usize);

pub fn success_response(id: Value, result: Value) -> Value {
    json!({
        "id": id,
        "result": result,
        "error": Value::Null,
    })
}

pub fn bool_response(id: Value, accepted: bool) -> Value {
    success_response(id, Value::Bool(accepted))
}

pub fn submit_error_response(id: Value, message: impl Into<String>) -> Value {
    json!({
        "id": id,
        "result": false,
        "error": message.into(),
    })
}

pub fn json_rpc_error_response(id: Value, code: i64, message: impl Into<String>) -> Value {
    json!({
        "id": id,
        "result": Value::Null,
        "error": JsonRpcErrorObject {
            code,
            message: message.into(),
        },
    })
}

impl TryFrom<&[Value]> for Subscribe {
    type Error = String;

    fn try_from(params: &[Value]) -> Result<Self, Self::Error> {
        Ok(Self {
            user_agent: optional_string(params.first())?,
            session_id: optional_string(params.get(1))?,
            host: optional_string(params.get(2))?,
            port: optional_u16(params.get(3))?,
        })
    }
}

impl TryFrom<&[Value]> for Authorize {
    type Error = String;

    fn try_from(params: &[Value]) -> Result<Self, Self::Error> {
        let worker_name = required_string(params.first(), "worker name")?;
        let password = optional_string(params.get(1))?;
        Ok(Self {
            worker_name,
            password,
        })
    }
}

impl TryFrom<&[Value]> for ExtranonceSubscribe {
    type Error = String;

    fn try_from(_params: &[Value]) -> Result<Self, Self::Error> {
        Ok(Self)
    }
}

impl TryFrom<&[Value]> for Submit {
    type Error = String;

    fn try_from(params: &[Value]) -> Result<Self, Self::Error> {
        Ok(Self {
            worker_name: required_string(params.first(), "worker name")?,
            job_id: required_string(params.get(1), "job id")?,
            time_hex: required_string(params.get(2), "ntime")?,
            nonce_2_hex: required_string(params.get(3), "nonce_2")?,
            solution_hex: required_string(params.get(4), "solution")?,
        })
    }
}

fn required_string(value: Option<&Value>, name: &str) -> Result<String, String> {
    let value = value.ok_or_else(|| format!("missing {}", name))?;
    value
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| format!("{} must be a string", name))
}

fn optional_string(value: Option<&Value>) -> Result<Option<String>, String> {
    match value {
        None => Ok(None),
        Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(other) => Err(format!("expected string or null, got {}", other)),
    }
}

fn optional_u16(value: Option<&Value>) -> Result<Option<u16>, String> {
    match value {
        None => Ok(None),
        Some(Value::Null) => Ok(None),
        Some(Value::Number(number)) => number
            .as_u64()
            .ok_or_else(|| "port must be an unsigned integer".to_string())
            .and_then(|port| {
                u16::try_from(port).map(Some).map_err(|_| "port out of range".to_string())
            }),
        Some(Value::String(text)) => text
            .parse::<u16>()
            .map(Some)
            .map_err(|error| format!("invalid port '{}': {}", text, error)),
        Some(other) => Err(format!("expected integer/string/null port, got {}", other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_submit_request() {
        let params = vec![
            Value::String("wallet.worker".into()),
            Value::String("42".into()),
            Value::String("65af3c12".into()),
            Value::String("0011".into()),
            Value::String("aa".repeat(1344)),
        ];
        let submit = Submit::try_from(params.as_slice()).unwrap();
        assert_eq!(submit.job_id, "42");
        assert_eq!(submit.nonce_2_hex, "0011");
    }
}
