// Copyright 2025, Offchain Labs, Inc.
// Cross-Environment Debug Bridge Client for Stylus
//
// This module provides communication with the SolDB cross-environment debug bridge,
// enabling Stylus contracts to interact with Solidity trace data.

use eyre::{bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// Protocol version for cross-environment debugging
pub const PROTOCOL_VERSION: &str = "1.0";

/// Default bridge server URL
pub const DEFAULT_BRIDGE_URL: &str = "http://127.0.0.1:8765";

/// Environment type for contracts
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Environment {
    Evm,
    Stylus,
}

impl std::fmt::Display for Environment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Environment::Evm => write!(f, "evm"),
            Environment::Stylus => write!(f, "stylus"),
        }
    }
}

/// Source code location
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceLocation {
    pub file: String,
    pub line: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column: Option<u32>,
}

/// Function call argument
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallArgument {
    pub name: String,
    #[serde(rename = "type")]
    pub arg_type: String,
    pub value: String,
}

/// A single call in the cross-environment trace
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossEnvCall {
    pub call_id: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_call_id: Option<u64>,
    pub environment: String,
    pub contract_address: String,
    pub function_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function_selector: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function_signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_location: Option<SourceLocation>,
    #[serde(default)]
    pub args: Vec<CallArgument>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas_used: Option<u64>,
    #[serde(default = "default_true")]
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub call_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<u64>,
    #[serde(default)]
    pub children: Vec<CrossEnvCall>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cross_env_ref: Option<String>,
}

fn default_true() -> bool {
    true
}

/// Complete cross-environment trace
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossEnvTrace {
    pub trace_id: String,
    #[serde(default = "default_protocol_version")]
    pub protocol_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_call: Option<CrossEnvCall>,
    #[serde(default)]
    pub calls: Vec<CrossEnvCall>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas_used: Option<u64>,
    #[serde(default = "default_true")]
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

fn default_protocol_version() -> String {
    PROTOCOL_VERSION.to_string()
}

/// Contract information for registration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractInfo {
    pub address: String,
    pub environment: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub debug_dir: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lib_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_path: Option<String>,
}

/// Trace request to another environment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceRequest {
    pub request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_number: Option<u64>,
    pub target_address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caller_address: Option<String>,
    pub calldata: String,
    #[serde(default)]
    pub value: u64,
    #[serde(default)]
    pub depth: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_call_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_trace_id: Option<String>,
    pub source_environment: String,
}

/// Trace response from the bridge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceResponse {
    pub request_id: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace: Option<CrossEnvTrace>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
}

/// Health check response
#[derive(Debug, Clone, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub protocol_version: String,
    pub contracts_registered: u32,
}

/// Contract list response
#[derive(Debug, Clone, Deserialize)]
pub struct ContractsResponse {
    pub contracts: Vec<ContractInfo>,
    pub count: u32,
}

/// Bridge client for cross-environment debugging
pub struct SoldbBridgeClient {
    bridge_url: String,
    client: reqwest::blocking::Client,
    connected: bool,
}

impl SoldbBridgeClient {
    /// Create a new bridge client
    pub fn new(bridge_url: Option<&str>) -> Self {
        let url = bridge_url.unwrap_or(DEFAULT_BRIDGE_URL).to_string();
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            bridge_url: url,
            client,
            connected: false,
        }
    }

    /// Get the bridge URL
    pub fn bridge_url(&self) -> &str {
        &self.bridge_url
    }

    /// Check if connected
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Connect to the bridge server
    pub fn connect(&mut self) -> Result<bool> {
        self.connected = self.health_check().is_ok();
        Ok(self.connected)
    }

    /// Check bridge server health
    pub fn health_check(&self) -> Result<HealthResponse> {
        let url = format!("{}/health", self.bridge_url);
        let response = self.client.get(&url).send()?;

        if !response.status().is_success() {
            bail!("Health check failed: {}", response.status());
        }

        let health: HealthResponse = response.json()?;
        Ok(health)
    }

    /// Register a contract with the bridge
    pub fn register_contract(&self, contract: &ContractInfo) -> Result<()> {
        let url = format!("{}/register", self.bridge_url);
        let response = self.client.post(&url).json(contract).send()?;

        if !response.status().is_success() {
            let text = response.text().unwrap_or_default();
            bail!("Failed to register contract: {}", text);
        }

        Ok(())
    }

    /// Register a Stylus contract
    pub fn register_stylus_contract(
        &self,
        address: &str,
        name: &str,
        lib_path: Option<&str>,
    ) -> Result<()> {
        let contract = ContractInfo {
            address: address.to_string(),
            environment: "stylus".to_string(),
            name: name.to_string(),
            debug_dir: None,
            lib_path: lib_path.map(String::from),
            project_path: None,
        };
        self.register_contract(&contract)
    }

    /// Register an EVM contract
    pub fn register_evm_contract(
        &self,
        address: &str,
        name: &str,
        debug_dir: Option<&str>,
        project_path: &str,
    ) -> Result<()> {
        let contract = ContractInfo {
            address: address.to_string(),
            environment: "evm".to_string(),
            name: name.to_string(),
            debug_dir: debug_dir.map(String::from),
            lib_path: None,
            project_path: Some(project_path.to_string()),
        };
        self.register_contract(&contract)
    }

    /// Get contract info by address
    pub fn get_contract(&self, address: &str) -> Result<Option<ContractInfo>> {
        let url = format!("{}/contract/{}", self.bridge_url, address);
        let response = self.client.get(&url).send()?;

        if response.status().as_u16() == 404 {
            return Ok(None);
        }

        if !response.status().is_success() {
            bail!("Failed to get contract: {}", response.status());
        }

        let contract: ContractInfo = response.json()?;
        Ok(Some(contract))
    }

    /// List all registered contracts
    pub fn list_contracts(&self) -> Result<Vec<ContractInfo>> {
        let url = format!("{}/contracts", self.bridge_url);
        let response = self.client.get(&url).send()?;

        if !response.status().is_success() {
            bail!("Failed to list contracts: {}", response.status());
        }

        let contracts: ContractsResponse = response.json()?;
        Ok(contracts.contracts)
    }

    /// Check if address is an EVM contract
    pub fn is_evm_contract(&self, address: &str) -> bool {
        self.get_contract(address)
            .ok()
            .flatten()
            .map(|c| c.environment == "evm")
            .unwrap_or(false)
    }

    /// Check if address is a Stylus contract
    pub fn is_stylus_contract(&self, address: &str) -> bool {
        self.get_contract(address)
            .ok()
            .flatten()
            .map(|c| c.environment == "stylus")
            .unwrap_or(false)
    }

    /// Request a trace from the EVM environment
    pub fn request_evm_trace(&self, request: &TraceRequest) -> Result<TraceResponse> {
        let url = format!("{}/request-trace", self.bridge_url);
        let response = self.client.post(&url).json(request).send()?;

        if !response.status().is_success() {
            let text = response.text().unwrap_or_default();
            bail!("Failed to request trace: {}", text);
        }

        let trace_response: TraceResponse = response.json()?;
        Ok(trace_response)
    }

    /// Submit a Stylus trace to the bridge
    pub fn submit_trace(&self, trace: &CrossEnvTrace) -> Result<()> {
        let url = format!("{}/submit-trace", self.bridge_url);
        let response = self.client.post(&url).json(trace).send()?;

        if !response.status().is_success() {
            let text = response.text().unwrap_or_default();
            bail!("Failed to submit trace: {}", text);
        }

        Ok(())
    }

    /// Get a trace by ID
    pub fn get_trace(&self, trace_id: &str) -> Result<Option<CrossEnvTrace>> {
        let url = format!("{}/trace/{}", self.bridge_url, trace_id);
        let response = self.client.get(&url).send()?;

        if response.status().as_u16() == 404 {
            return Ok(None);
        }

        if !response.status().is_success() {
            bail!("Failed to get trace: {}", response.status());
        }

        let trace: CrossEnvTrace = response.json()?;
        Ok(Some(trace))
    }
}

/// Solidity contract info for cross-env tracing
#[derive(Debug, Clone)]
pub struct SolidityContractInfo {
    pub name: String,
    pub debug_dir: String,
    pub project_path: Option<String>,
}

/// Configuration for cross-environment tracing
#[derive(Debug, Clone)]
pub struct CrossEnvConfig {
    pub bridge_url: String,
    pub solidity_contracts: HashMap<String, SolidityContractInfo>,
    pub tx_hash: Option<String>,
    pub rpc_endpoint: String,
    pub caller_address: Option<String>,
    pub block_number: Option<u64>,
}

/// Global cross-env configuration
static mut CROSS_ENV_CONFIG: Option<CrossEnvConfig> = None;

/// Set the cross-environment configuration
pub fn set_cross_env_config(config: CrossEnvConfig) {
    unsafe {
        CROSS_ENV_CONFIG = Some(config);
    }
}

/// Get the cross-environment configuration
pub fn get_cross_env_config() -> Option<&'static CrossEnvConfig> {
    unsafe { CROSS_ENV_CONFIG.as_ref() }
}

/// Check if an address is a registered Solidity contract
pub fn is_solidity_contract(address: &str) -> bool {
    let normalized = address.to_lowercase();
    unsafe {
        CROSS_ENV_CONFIG
            .as_ref()
            .map(|c| c.solidity_contracts.contains_key(&normalized))
            .unwrap_or(false)
    }
}

/// Get Solidity contract info by address
pub fn get_solidity_contract(address: &str) -> Option<&'static SolidityContractInfo> {
    let normalized = address.to_lowercase();
    unsafe {
        CROSS_ENV_CONFIG
            .as_ref()
            .and_then(|c| c.solidity_contracts.get(&normalized))
    }
}

/// Global bridge client instance
static mut BRIDGE_CLIENT: Option<SoldbBridgeClient> = None;

/// Get or create the global bridge client
pub fn get_bridge_client() -> &'static SoldbBridgeClient {
    unsafe {
        if BRIDGE_CLIENT.is_none() {
            BRIDGE_CLIENT = Some(SoldbBridgeClient::new(None));
        }
        BRIDGE_CLIENT.as_ref().unwrap()
    }
}

/// Set the bridge URL and reset the client
pub fn set_bridge_url(url: &str) {
    unsafe {
        BRIDGE_CLIENT = Some(SoldbBridgeClient::new(Some(url)));
    }
}

/// Helper to create a trace request
pub fn create_trace_request(
    target_address: &str,
    calldata: &str,
    caller: Option<&str>,
    value: u64,
    depth: u32,
    parent_call_id: Option<u64>,
    tx_hash: Option<&str>,
) -> TraceRequest {
    TraceRequest {
        request_id: uuid::Uuid::new_v4().to_string(),
        transaction_hash: tx_hash.map(String::from),
        block_number: None,
        target_address: target_address.to_string(),
        caller_address: caller.map(String::from),
        calldata: calldata.to_string(),
        value,
        depth,
        parent_call_id,
        parent_trace_id: None,
        source_environment: "stylus".to_string(),
    }
}

/// Request EVM trace via the bridge server and wait for completion
pub fn request_and_wait_evm_trace(
    target_address: &str,
    calldata: &str,
    value: u64,
    caller: Option<&str>,
    depth: u32,
    parent_call_id: Option<u64>,
) -> Result<Option<CrossEnvTrace>> {
    let config = get_cross_env_config().ok_or_else(|| eyre::eyre!("Cross-env config not set"))?;

    let client = SoldbBridgeClient::new(Some(&config.bridge_url));

    let request = TraceRequest {
        request_id: uuid::Uuid::new_v4().to_string(),
        transaction_hash: config.tx_hash.clone(),
        block_number: None,
        target_address: target_address.to_string(),
        caller_address: caller.map(String::from),
        calldata: calldata.to_string(),
        value,
        depth,
        parent_call_id,
        parent_trace_id: None,
        source_environment: "stylus".to_string(),
    };

    let response = client.request_evm_trace(&request)?;

    match response.status.as_str() {
        "success" => Ok(response.trace),
        "pending" => {
            // Poll for completion
            for _ in 0..30 {
                std::thread::sleep(std::time::Duration::from_millis(100));
                if let Ok(Some(trace)) = client.get_trace(&request.request_id) {
                    return Ok(Some(trace));
                }
            }
            bail!("Timeout waiting for EVM trace")
        }
        "error" => {
            bail!(
                "EVM trace request failed: {}",
                response.error_message.unwrap_or_default()
            )
        }
        _ => bail!("Unknown trace response status: {}", response.status),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contract_info_serialization() {
        let contract = ContractInfo {
            address: "0x1234567890abcdef1234567890abcdef12345678".to_string(),
            environment: "stylus".to_string(),
            name: "TestContract".to_string(),
            debug_dir: None,
            lib_path: Some("/path/to/lib.dylib".to_string()),
            project_path: None,
        };

        let json = serde_json::to_string(&contract).unwrap();
        assert!(json.contains("stylus"));
        assert!(json.contains("TestContract"));
    }

    #[test]
    fn test_cross_env_call_serialization() {
        let call = CrossEnvCall {
            call_id: 1,
            parent_call_id: None,
            environment: "stylus".to_string(),
            contract_address: "0x1234".to_string(),
            function_name: "increment".to_string(),
            function_selector: Some("0x12345678".to_string()),
            function_signature: None,
            source_location: Some(SourceLocation {
                file: "lib.rs".to_string(),
                line: 42,
                column: None,
            }),
            args: vec![CallArgument {
                name: "amount".to_string(),
                arg_type: "uint256".to_string(),
                value: "100".to_string(),
            }],
            return_data: None,
            return_value: None,
            gas_used: Some(21000),
            success: true,
            error: None,
            call_type: "external".to_string(),
            value: None,
            children: vec![],
            cross_env_ref: None,
        };

        let json = serde_json::to_string(&call).unwrap();
        assert!(json.contains("increment"));
        assert!(json.contains("lib.rs"));
    }
}
