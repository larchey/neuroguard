//! Policy engine for capability-based access control

use crate::error::{Error, Result};
use crate::protocol::{DecodedOutput, NeuralChannel};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Policy engine for neural access control
pub struct PolicyEngine {
    /// Application policies
    policies: HashMap<String, ApplicationPolicy>,

    /// Global restrictions
    global_restrictions: GlobalRestrictions,
}

/// Policy for an application
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicationPolicy {
    /// Application identifier
    pub app_id: String,

    /// Allowed capabilities
    pub capabilities: HashSet<Capability>,

    /// Channel access rules
    pub channel_access: ChannelAccessRule,

    /// Rate limits
    pub rate_limit: RateLimit,

    /// Allowed output types
    pub allowed_outputs: HashSet<OutputType>,
}

/// Neural capabilities
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Capability {
    /// Read raw neural signals
    ReadRawSignal,

    /// Read decoded outputs only
    ReadDecodedOutput,

    /// Access motor cortex channels
    AccessMotorCortex,

    /// Access sensory cortex channels
    AccessSensoryCortex,

    /// Access visual cortex channels
    AccessVisualCortex,

    /// Access auditory cortex channels
    AccessAuditoryCortex,

    /// Control external devices
    ControlDevice,

    /// Record neural data
    RecordData,

    /// Perform calibration
    Calibrate,
}

/// Channel access rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChannelAccessRule {
    /// Allow all channels
    AllChannels,

    /// Allow specific channels only
    Whitelist(HashSet<u32>),

    /// Deny specific channels
    Blacklist(HashSet<u32>),

    /// No channel access
    None,
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimit {
    /// Maximum frames per second
    pub max_fps: u32,

    /// Maximum data rate (bytes/sec)
    pub max_bytes_per_sec: u64,
}

/// Output types
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum OutputType {
    /// Cursor position
    Cursor,

    /// Discrete commands
    Command,

    /// Text/speech
    Text,

    /// Prosthetic control
    Prosthetic,

    /// Vehicle control
    Vehicle,

    /// Raw classification
    Classification,
}

/// Global system restrictions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalRestrictions {
    /// Maximum signal data size per frame
    pub max_signal_size: usize,

    /// Require encryption for raw signals
    pub require_encryption: bool,

    /// Blacklisted applications
    pub blacklisted_apps: HashSet<String>,

    /// Minimum device trust level required
    pub min_trust_level: String,
}

impl PolicyEngine {
    /// Create a new policy engine
    pub fn new() -> Self {
        Self {
            policies: HashMap::new(),
            global_restrictions: GlobalRestrictions {
                max_signal_size: 1_000_000, // 1M samples max
                require_encryption: true,
                blacklisted_apps: HashSet::new(),
                min_trust_level: "provisional".to_string(),
            },
        }
    }

    /// Register an application policy
    pub fn register_policy(&mut self, policy: ApplicationPolicy) {
        self.policies.insert(policy.app_id.clone(), policy);
    }

    /// Check if an application has a capability
    pub fn check_capability(&self, app_id: &str, capability: Capability) -> Result<()> {
        // Check if app is blacklisted
        if self.global_restrictions.blacklisted_apps.contains(app_id) {
            return Err(Error::ApplicationUnauthorized(format!(
                "application {} is blacklisted",
                app_id
            )));
        }

        let policy = self
            .policies
            .get(app_id)
            .ok_or_else(|| Error::ApplicationUnauthorized(format!("no policy for {}", app_id)))?;

        if policy.capabilities.contains(&capability) {
            Ok(())
        } else {
            Err(Error::CapabilityDenied {
                capability: format!("{:?}", capability),
            })
        }
    }

    /// Check if an application can access a channel
    pub fn check_channel_access(&self, app_id: &str, channel: &NeuralChannel) -> Result<()> {
        let policy = self
            .policies
            .get(app_id)
            .ok_or_else(|| Error::ApplicationUnauthorized(format!("no policy for {}", app_id)))?;

        match &policy.channel_access {
            ChannelAccessRule::AllChannels => Ok(()),
            ChannelAccessRule::Whitelist(allowed) => {
                if allowed.contains(&channel.id) {
                    Ok(())
                } else {
                    Err(Error::PolicyViolation(format!(
                        "channel {} not in whitelist",
                        channel.id
                    )))
                }
            }
            ChannelAccessRule::Blacklist(denied) => {
                if denied.contains(&channel.id) {
                    Err(Error::PolicyViolation(format!(
                        "channel {} is blacklisted",
                        channel.id
                    )))
                } else {
                    Ok(())
                }
            }
            ChannelAccessRule::None => Err(Error::PolicyViolation("no channel access".to_string())),
        }
    }

    /// Check if an output type is allowed
    pub fn check_output_type(&self, app_id: &str, output: &DecodedOutput) -> Result<()> {
        let policy = self
            .policies
            .get(app_id)
            .ok_or_else(|| Error::ApplicationUnauthorized(format!("no policy for {}", app_id)))?;

        let output_type = match output {
            DecodedOutput::CursorPosition { .. } => OutputType::Cursor,
            DecodedOutput::Command(_) => OutputType::Command,
            DecodedOutput::Text(_) => OutputType::Text,
            DecodedOutput::ProstheticControl { .. } => OutputType::Prosthetic,
            DecodedOutput::VehicleControl { .. } => OutputType::Vehicle,
            DecodedOutput::Classification { .. } => OutputType::Classification,
        };

        if policy.allowed_outputs.contains(&output_type) {
            Ok(())
        } else {
            Err(Error::PolicyViolation(format!(
                "output type {:?} not allowed",
                output_type
            )))
        }
    }

    /// Blacklist an application
    pub fn blacklist_app(&mut self, app_id: String) {
        self.global_restrictions.blacklisted_apps.insert(app_id);
    }

    /// Create a default policy for testing/development
    pub fn default_dev_policy(app_id: String) -> ApplicationPolicy {
        ApplicationPolicy {
            app_id,
            capabilities: HashSet::from([
                Capability::ReadDecodedOutput,
                Capability::AccessMotorCortex,
            ]),
            channel_access: ChannelAccessRule::AllChannels,
            rate_limit: RateLimit {
                max_fps: 60,
                max_bytes_per_sec: 1_000_000,
            },
            allowed_outputs: HashSet::from([
                OutputType::Cursor,
                OutputType::Command,
                OutputType::Classification,
            ]),
        }
    }

    /// Create a strict production policy
    pub fn strict_policy(app_id: String, allowed_channels: Vec<u32>) -> ApplicationPolicy {
        ApplicationPolicy {
            app_id,
            capabilities: HashSet::from([Capability::ReadDecodedOutput]),
            channel_access: ChannelAccessRule::Whitelist(allowed_channels.into_iter().collect()),
            rate_limit: RateLimit {
                max_fps: 30,
                max_bytes_per_sec: 100_000,
            },
            allowed_outputs: HashSet::from([OutputType::Cursor, OutputType::Command]),
        }
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::ChannelType;

    #[test]
    fn test_capability_check() {
        let mut engine = PolicyEngine::new();

        let policy = ApplicationPolicy {
            app_id: "test-app".to_string(),
            capabilities: HashSet::from([Capability::ReadDecodedOutput]),
            channel_access: ChannelAccessRule::AllChannels,
            rate_limit: RateLimit {
                max_fps: 60,
                max_bytes_per_sec: 1_000_000,
            },
            allowed_outputs: HashSet::new(),
        };

        engine.register_policy(policy);

        assert!(engine
            .check_capability("test-app", Capability::ReadDecodedOutput)
            .is_ok());
        assert!(engine
            .check_capability("test-app", Capability::ReadRawSignal)
            .is_err());
    }

    #[test]
    fn test_channel_access() {
        let mut engine = PolicyEngine::new();

        let policy = ApplicationPolicy {
            app_id: "test-app".to_string(),
            capabilities: HashSet::new(),
            channel_access: ChannelAccessRule::Whitelist(HashSet::from([1, 2, 3])),
            rate_limit: RateLimit {
                max_fps: 60,
                max_bytes_per_sec: 1_000_000,
            },
            allowed_outputs: HashSet::new(),
        };

        engine.register_policy(policy);

        let channel_allowed = NeuralChannel {
            id: 1,
            channel_type: ChannelType::Motor,
            sample_rate: 1000,
            quality: 0.9,
        };

        let channel_denied = NeuralChannel {
            id: 99,
            channel_type: ChannelType::Motor,
            sample_rate: 1000,
            quality: 0.9,
        };

        assert!(engine.check_channel_access("test-app", &channel_allowed).is_ok());
        assert!(engine.check_channel_access("test-app", &channel_denied).is_err());
    }

    #[test]
    fn test_blacklist() {
        let mut engine = PolicyEngine::new();

        engine.register_policy(PolicyEngine::default_dev_policy("test-app".to_string()));

        // Should work before blacklist
        assert!(engine
            .check_capability("test-app", Capability::ReadDecodedOutput)
            .is_ok());

        // Blacklist the app
        engine.blacklist_app("test-app".to_string());

        // Should fail after blacklist
        assert!(engine
            .check_capability("test-app", Capability::ReadDecodedOutput)
            .is_err());
    }
}
