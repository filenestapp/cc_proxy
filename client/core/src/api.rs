//! Control plane client API (`/v1/*`).

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Entry {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginResponse {
    pub token: String,
    pub user: String,
    pub device: String,
    pub egress_ip: Option<String>,
    pub entry: Option<Entry>,
    #[serde(default)]
    pub host: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Me {
    pub user: String,
    pub device: String,
    pub egress_ip: Option<String>,
    pub entry: Option<Entry>,
    #[serde(default)]
    pub host: Option<String>,
}

/// Result of polling the config.
#[derive(Debug)]
pub enum ConfigFetch {
    /// New content, with its ETag.
    Changed { etag: String, body: Vec<u8> },
    /// Same as the ETag we sent.
    NotModified,
    /// The device token no longer works: signed out elsewhere, revoked, or the password was reset.
    Unauthorized,
    /// Signed in, but no exit IP is bound to the user (yet).
    Unassigned(String),
}

#[derive(Debug)]
pub enum LoginError {
    WrongCredentials,
    TooManyAttempts,
    Rejected(String),
    Network(String),
}

impl std::error::Error for LoginError {}

impl std::fmt::Display for LoginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoginError::WrongCredentials => write!(f, "用户名或密码错误"),
            LoginError::TooManyAttempts => write!(f, "登录失败次数过多，请稍后再试"),
            LoginError::Rejected(m) => write!(f, "{m}"),
            LoginError::Network(m) => write!(f, "无法连接控制端：{m}"),
        }
    }
}

pub struct Api {
    base: String,
    agent: ureq::Agent,
}

fn error_message(resp: ureq::Response) -> String {
    let status = resp.status();
    resp.into_json::<serde_json::Value>()
        .ok()
        .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(String::from))
        .unwrap_or_else(|| format!("HTTP {status}"))
}

impl Api {
    pub fn new(base: &str) -> Result<Self> {
        let base = base.trim().trim_end_matches('/').to_string();
        if !(base.starts_with("https://") || base.starts_with("http://")) {
            return Err(anyhow!("server address must start with https:// (or http:// for local testing)"));
        }
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(10))
            .timeout(Duration::from_secs(20))
            .user_agent(concat!("ccproxy/", env!("CARGO_PKG_VERSION")))
            .build();
        Ok(Api { base, agent })
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    pub fn login(&self, username: &str, password: &str, device: &str, platform: &str) -> Result<LoginResponse, LoginError> {
        let body = serde_json::json!({"username": username, "password": password, "device": device, "platform": platform});
        match self.agent.post(&format!("{}/v1/login", self.base)).send_json(body) {
            Ok(resp) => resp.into_json().map_err(|e| LoginError::Network(e.to_string())),
            Err(ureq::Error::Status(401, _)) => Err(LoginError::WrongCredentials),
            Err(ureq::Error::Status(429, _)) => Err(LoginError::TooManyAttempts),
            Err(ureq::Error::Status(_, resp)) => Err(LoginError::Rejected(error_message(resp))),
            Err(e) => Err(LoginError::Network(e.to_string())),
        }
    }

    pub fn me(&self, token: &str) -> Result<Option<Me>> {
        match self.agent.get(&format!("{}/v1/me", self.base)).set("Authorization", &format!("Bearer {token}")).call() {
            Ok(resp) => Ok(Some(resp.into_json()?)),
            Err(ureq::Error::Status(401, _)) => Ok(None),
            Err(ureq::Error::Status(_, resp)) => Err(anyhow!(error_message(resp))),
            Err(e) => Err(anyhow!(e)).context("contacting control plane"),
        }
    }

    pub fn config(&self, token: &str, mode: &str, etag: Option<&str>) -> Result<ConfigFetch> {
        let mut req = self
            .agent
            .get(&format!("{}/v1/config", self.base))
            .query("mode", mode)
            .set("Authorization", &format!("Bearer {token}"));
        if let Some(tag) = etag {
            req = req.set("If-None-Match", tag);
        }
        match req.call() {
            Ok(resp) if resp.status() == 304 => Ok(ConfigFetch::NotModified),
            Ok(resp) => {
                let etag = resp.header("ETag").unwrap_or_default().to_string();
                let mut body = Vec::new();
                std::io::Read::read_to_end(&mut resp.into_reader(), &mut body)?;
                serde_json::from_slice::<serde_json::Value>(&body).context("config is not JSON")?;
                Ok(ConfigFetch::Changed { etag, body })
            }
            Err(ureq::Error::Status(304, _)) => Ok(ConfigFetch::NotModified),
            Err(ureq::Error::Status(401, _)) => Ok(ConfigFetch::Unauthorized),
            Err(ureq::Error::Status(409, resp)) => Ok(ConfigFetch::Unassigned(error_message(resp))),
            Err(ureq::Error::Status(_, resp)) => Err(anyhow!(error_message(resp))),
            Err(e) => Err(anyhow!(e)).context("contacting control plane"),
        }
    }

    pub fn logout(&self, token: &str) -> Result<()> {
        match self.agent.post(&format!("{}/v1/logout", self.base)).set("Authorization", &format!("Bearer {token}")).call() {
            Ok(_) | Err(ureq::Error::Status(401, _)) => Ok(()),
            Err(ureq::Error::Status(_, resp)) => Err(anyhow!(error_message(resp))),
            Err(e) => Err(anyhow!(e)).context("contacting control plane"),
        }
    }
}
