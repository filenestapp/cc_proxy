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

/// Result of polling the XTCP visitor settings.
#[derive(Debug)]
pub enum VisitorFetch {
    Changed { etag: String, body: Vec<u8> },
    NotModified,
    /// 204: the exit host uses the public entry, no visitor is needed.
    NotNeeded,
    Unauthorized,
    /// 409: no visitor can be given (no exit, no mapping, or the host is misconfigured). Carries the reason.
    Unavailable(String),
    /// 404: a control plane from before issue #61, without the endpoint. It cannot hand out a visitor, so the client
    /// keeps the previous behaviour: a public-entry host works as before, an XTCP host needs a hand-run visitor.
    Unsupported,
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
            LoginError::WrongCredentials => write!(f, "Incorrect username or password."),
            LoginError::TooManyAttempts => write!(f, "Too many sign-in attempts. Try again later."),
            LoginError::Rejected(m) => write!(f, "{m}"),
            LoginError::Network(m) => write!(f, "Could not reach the control plane: {m}"),
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
            .user_agent(concat!("aifree/", env!("CARGO_PKG_VERSION")))
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

    /// `GET /v1/xtcp-visitor`: this device's XTCP visitor settings. The body holds the frps token: never log it.
    pub fn xtcp_visitor(&self, token: &str, etag: Option<&str>) -> Result<VisitorFetch> {
        let mut req = self.agent.get(&format!("{}/v1/xtcp-visitor", self.base)).set("Authorization", &format!("Bearer {token}"));
        if let Some(tag) = etag {
            req = req.set("If-None-Match", tag);
        }
        match req.call() {
            Ok(resp) if resp.status() == 304 => Ok(VisitorFetch::NotModified),
            Ok(resp) if resp.status() == 204 => Ok(VisitorFetch::NotNeeded),
            Ok(resp) => {
                let etag = resp.header("ETag").unwrap_or_default().to_string();
                let mut body = Vec::new();
                std::io::Read::read_to_end(&mut std::io::Read::take(resp.into_reader(), 1 << 20), &mut body)?;
                Ok(VisitorFetch::Changed { etag, body })
            }
            Err(ureq::Error::Status(304, _)) => Ok(VisitorFetch::NotModified),
            Err(ureq::Error::Status(401, _)) => Ok(VisitorFetch::Unauthorized),
            Err(ureq::Error::Status(409, resp)) => Ok(VisitorFetch::Unavailable(error_message(resp))),
            Err(ureq::Error::Status(404, _)) => Ok(VisitorFetch::Unsupported),
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
