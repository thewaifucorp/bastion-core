//! An owner's devices: identity, role, what each may run, and the signed
//! registry that admits them (BMD-08, BMD-10).
//!
//! A device is admitted only with an [`Enrollment`] signed by the owner key
//! **and** an [`EnrollmentApproval`] signed by a device already in the
//! registry — the "pair on a device you already trust" step. Grants start
//! empty (BMD-03); every change to them is a new owner-signed enrollment, so
//! a node can check on its own that an order is covered by what the owner
//! granted.

use std::collections::BTreeMap;

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::identity::age_identity::{canonical_json_string, AgeIdentity};

/// Stable per installation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DeviceId(pub String);

impl DeviceId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for DeviceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    Linux,
    Windows,
    MacOs,
}

impl Platform {
    /// The platform this binary was built for.
    pub fn current() -> Self {
        if cfg!(windows) {
            Self::Windows
        } else if cfg!(target_os = "macos") {
            Self::MacOs
        } else {
            Self::Linux
        }
    }
}

/// A device's role in the owner's set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "role", rename_all = "snake_case")]
pub enum Role {
    /// Source of truth during `epoch`. At most one per owner per epoch.
    Primary { epoch: u64 },
    /// Executor; `replica` says whether it keeps a replica.
    Node { replica: bool },
}

/// What a granted capability may touch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "items", rename_all = "snake_case")]
pub enum GrantScope {
    /// Only these applications (executable names, case-insensitive).
    Apps(Vec<String>),
    /// Only paths under these directories.
    Paths(Vec<String>),
    Any,
}

impl GrantScope {
    /// Whether `app` (an executable name or path) is inside the scope.
    pub fn allows_app(&self, app: &str) -> bool {
        let name = app
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or(app)
            .to_ascii_lowercase();
        match self {
            Self::Any => true,
            Self::Apps(apps) => apps.iter().any(|a| a.to_ascii_lowercase() == name),
            Self::Paths(_) => false,
        }
    }

    /// Whether `path` is under one of the scope's directories. Compares
    /// components, so `/data-other` is not under `/data`.
    pub fn allows_path(&self, path: &std::path::Path) -> bool {
        match self {
            Self::Any => true,
            Self::Apps(_) => false,
            Self::Paths(roots) => roots
                .iter()
                .any(|root| path.starts_with(std::path::Path::new(root))),
        }
    }
}

/// One capability the owner lets a device run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityGrant {
    /// e.g. `ui.act`, `system.run`.
    pub capability: String,
    pub scope: GrantScope,
    /// The primary may only harden this, never relax it: a node refuses an
    /// order for a `needs_approval` grant that carries no approval.
    pub needs_approval: bool,
}

/// Raw 32-byte keys travel as base64url, like `AgentCard`'s keys.
mod key_b64 {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(key: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let text = String::deserialize(d)?;
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(text)
            .map_err(serde::de::Error::custom)?
            .try_into()
            .map_err(|_| serde::de::Error::custom("key must be 32 bytes"))
    }
}

pub(crate) mod sig_b64 {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(sig: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(d)?;
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(text)
            .map_err(serde::de::Error::custom)
    }
}

/// A device of the owner, signed by the owner key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Enrollment {
    pub owner: String,
    pub device: DeviceId,
    /// Ed25519 public key (the device's `bastion-mesh` identity).
    #[serde(with = "key_b64")]
    pub device_key: [u8; 32],
    /// The device's secrets key (age X25519 recipient, bech32): secrets the
    /// owner lets this device keep are encrypted to it (§5.7). Its private
    /// half stays wrapped on the device and is unwrapped only at promotion,
    /// with the owner present. `None`: the device keeps no secrets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secrets_recipient: Option<String>,
    pub platform: Platform,
    pub holds_replica: bool,
    /// Empty at first (BMD-03).
    pub granted: Vec<CapabilityGrant>,
    /// Increases with every re-signed version of this device's enrollment,
    /// so an older one can never replace a newer one.
    #[serde(default)]
    pub revision: u64,
    #[serde(with = "sig_b64", default)]
    pub owner_signature: Vec<u8>,
}

/// Domain separators: a signature made for one purpose never verifies for
/// another.
const ENROLLMENT_DOMAIN: &[u8] = b"bastion-device-enrollment-v1\0";
const APPROVAL_DOMAIN: &[u8] = b"bastion-device-approval-v1\0";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EnrollmentError {
    #[error("the enrollment is not signed by the owner key")]
    BadOwnerSignature,
    #[error("enrollment for owner {got:?}, registry is for {expected:?}")]
    WrongOwner { expected: String, got: String },
    #[error("the approval is not signed by a registered device")]
    BadApproval,
    #[error("approving device {0} is not registered or was revoked")]
    UnknownApprover(DeviceId),
    #[error("device {0} is not registered")]
    UnknownDevice(DeviceId),
    #[error("device {0} was revoked")]
    Revoked(DeviceId),
    #[error("device {0} is already registered with another key")]
    KeyMismatch(DeviceId),
    #[error("enrollment revision {got} for {device} is not newer than {current}")]
    StaleRevision {
        device: DeviceId,
        current: u64,
        got: u64,
    },
}

impl Enrollment {
    /// An unsigned enrollment with no grants.
    pub fn new(
        owner: impl Into<String>,
        device: DeviceId,
        device_key: [u8; 32],
        platform: Platform,
        holds_replica: bool,
    ) -> Self {
        Self {
            owner: owner.into(),
            device,
            device_key,
            secrets_recipient: None,
            platform,
            holds_replica,
            granted: Vec::new(),
            revision: 0,
            owner_signature: Vec::new(),
        }
    }

    /// The bytes the owner signs: every field but the signature, as canonical
    /// JSON (sorted keys), after a domain separator.
    fn signed_bytes(&self) -> Vec<u8> {
        let mut value = serde_json::to_value(self).expect("enrollment serializes");
        if let Some(object) = value.as_object_mut() {
            object.remove("owner_signature");
        }
        let mut bytes = ENROLLMENT_DOMAIN.to_vec();
        bytes.extend_from_slice(canonical_json_string(&value).as_bytes());
        bytes
    }

    /// SHA-256 of the signed bytes — what an approval refers to.
    pub fn digest(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        Sha256::digest(self.signed_bytes()).into()
    }

    pub fn sign(mut self, owner: &AgeIdentity) -> Self {
        self.owner_signature = owner.sign(&self.signed_bytes()).to_vec();
        self
    }

    pub fn verify(&self, owner_key: &[u8; 32]) -> Result<(), EnrollmentError> {
        verify(owner_key, &self.signed_bytes(), &self.owner_signature)
            .map_err(|()| EnrollmentError::BadOwnerSignature)
    }

    /// The grant for `capability`, if the owner gave one.
    pub fn grant(&self, capability: &str) -> Option<&CapabilityGrant> {
        self.granted.iter().find(|g| g.capability == capability)
    }
}

pub(crate) fn verify(key: &[u8; 32], message: &[u8], signature: &[u8]) -> Result<(), ()> {
    let key = VerifyingKey::from_bytes(key).map_err(|_| ())?;
    let signature = Signature::from_slice(signature).map_err(|_| ())?;
    key.verify_strict(message, &signature).map_err(|_| ())
}

/// "Yes, admit this device", said on a device already registered: its
/// signature over the enrollment's digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollmentApproval {
    pub approver: DeviceId,
    #[serde(with = "sig_b64")]
    pub signature: Vec<u8>,
}

impl EnrollmentApproval {
    pub fn sign(approver: DeviceId, key: &AgeIdentity, enrollment: &Enrollment) -> Self {
        Self {
            approver,
            signature: key.sign(&approval_bytes(enrollment)).to_vec(),
        }
    }
}

fn approval_bytes(enrollment: &Enrollment) -> Vec<u8> {
    let mut bytes = APPROVAL_DOMAIN.to_vec();
    bytes.extend_from_slice(&enrollment.digest());
    bytes
}

/// A secret the owner lets one device keep (§5.7). One grant per device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretGrant {
    /// Name in the Agent's storage (e.g. `anthropic_api_key`, `codex:work`).
    pub secret: String,
    pub device: DeviceId,
    pub granted_at: i64,
}

/// One registered device and what the registry knows about it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRecord {
    pub enrollment: Enrollment,
    pub role: Role,
    /// Address on the owner's private network, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(default)]
    pub revoked: bool,
    #[serde(default)]
    pub secret_grants: Vec<SecretGrant>,
}

/// When an epoch began: who became primary, and from which event of the
/// previous epoch's log (its replica's last `seq` at promotion).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochStart {
    pub epoch: u64,
    pub primary: DeviceId,
    pub after_seq: u64,
}

/// The owner's devices. Serializable: it is part of what replicates (§5.6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRegistry {
    owner: String,
    #[serde(with = "key_b64")]
    owner_key: [u8; 32],
    devices: BTreeMap<DeviceId, DeviceRecord>,
    #[serde(default)]
    epochs: Vec<EpochStart>,
}

impl DeviceRegistry {
    /// A registry whose first device is `primary`, at epoch 1. The first
    /// device needs no approval: there is nobody else to ask.
    pub fn bootstrap(
        owner_key: [u8; 32],
        primary: Enrollment,
        address: Option<String>,
    ) -> Result<Self, EnrollmentError> {
        primary.verify(&owner_key)?;
        let mut devices = BTreeMap::new();
        devices.insert(
            primary.device.clone(),
            DeviceRecord {
                role: Role::Primary { epoch: 1 },
                address,
                revoked: false,
                secret_grants: Vec::new(),
                enrollment: primary.clone(),
            },
        );
        Ok(Self {
            owner: primary.owner.clone(),
            owner_key,
            epochs: vec![EpochStart {
                epoch: 1,
                primary: primary.device.clone(),
                after_seq: 0,
            }],
            devices,
        })
    }

    pub fn owner(&self) -> &str {
        &self.owner
    }

    pub fn owner_key(&self) -> &[u8; 32] {
        &self.owner_key
    }

    /// Admit a new device (BMD-08): owner-signed enrollment plus an approval
    /// from a device already registered and not revoked. It joins as a node.
    pub fn admit(
        &mut self,
        enrollment: Enrollment,
        approval: &EnrollmentApproval,
    ) -> Result<&DeviceRecord, EnrollmentError> {
        self.check_owner(&enrollment)?;
        enrollment.verify(&self.owner_key)?;
        let approver = self
            .active(&approval.approver)
            .map_err(|_| EnrollmentError::UnknownApprover(approval.approver.clone()))?;
        verify(
            &approver.enrollment.device_key,
            &approval_bytes(&enrollment),
            &approval.signature,
        )
        .map_err(|()| EnrollmentError::BadApproval)?;
        if let Some(existing) = self.devices.get(&enrollment.device) {
            if existing.enrollment.device_key != enrollment.device_key {
                return Err(EnrollmentError::KeyMismatch(enrollment.device.clone()));
            }
            if existing.revoked {
                return Err(EnrollmentError::Revoked(enrollment.device.clone()));
            }
        }
        let device = enrollment.device.clone();
        let replica = enrollment.holds_replica;
        self.devices.insert(
            device.clone(),
            DeviceRecord {
                enrollment,
                role: Role::Node { replica },
                address: None,
                revoked: false,
                secret_grants: Vec::new(),
            },
        );
        Ok(&self.devices[&device])
    }

    /// Replace a device's enrollment with a newer owner-signed revision (new
    /// grants, replica flag). Same key, higher revision.
    pub fn update(&mut self, enrollment: Enrollment) -> Result<(), EnrollmentError> {
        self.check_owner(&enrollment)?;
        enrollment.verify(&self.owner_key)?;
        let record = self.active_mut(&enrollment.device)?;
        if record.enrollment.device_key != enrollment.device_key {
            return Err(EnrollmentError::KeyMismatch(enrollment.device.clone()));
        }
        if enrollment.revision <= record.enrollment.revision {
            return Err(EnrollmentError::StaleRevision {
                device: enrollment.device.clone(),
                current: record.enrollment.revision,
                got: enrollment.revision,
            });
        }
        if let Role::Node { replica } = &mut record.role {
            *replica = enrollment.holds_replica;
        }
        record.enrollment = enrollment;
        Ok(())
    }

    /// Revoke a device. Returns the secrets it kept, which the owner should
    /// rotate (BMD-33). The record stays (revoked), so the device can never be
    /// re-admitted with the same id silently.
    pub fn revoke(&mut self, device: &DeviceId) -> Result<Vec<SecretGrant>, EnrollmentError> {
        let record = self
            .devices
            .get_mut(device)
            .ok_or_else(|| EnrollmentError::UnknownDevice(device.clone()))?;
        record.revoked = true;
        Ok(std::mem::take(&mut record.secret_grants))
    }

    pub fn get(&self, device: &DeviceId) -> Option<&DeviceRecord> {
        self.devices.get(device)
    }

    /// A registered, not revoked device.
    pub fn active(&self, device: &DeviceId) -> Result<&DeviceRecord, EnrollmentError> {
        match self.devices.get(device) {
            None => Err(EnrollmentError::UnknownDevice(device.clone())),
            Some(record) if record.revoked => Err(EnrollmentError::Revoked(device.clone())),
            Some(record) => Ok(record),
        }
    }

    pub(crate) fn active_mut(
        &mut self,
        device: &DeviceId,
    ) -> Result<&mut DeviceRecord, EnrollmentError> {
        match self.devices.get_mut(device) {
            None => Err(EnrollmentError::UnknownDevice(device.clone())),
            Some(record) if record.revoked => Err(EnrollmentError::Revoked(device.clone())),
            Some(record) => Ok(record),
        }
    }

    pub fn devices(&self) -> impl Iterator<Item = &DeviceRecord> {
        self.devices.values()
    }

    /// The primary of the highest epoch, if any.
    pub fn primary(&self) -> Option<(&DeviceRecord, u64)> {
        self.devices
            .values()
            .filter(|r| !r.revoked)
            .filter_map(|r| match r.role {
                Role::Primary { epoch } => Some((r, epoch)),
                Role::Node { .. } => None,
            })
            .max_by_key(|(_, epoch)| *epoch)
    }

    pub fn set_address(
        &mut self,
        device: &DeviceId,
        address: Option<String>,
    ) -> Result<(), EnrollmentError> {
        self.active_mut(device)?.address = address;
        Ok(())
    }

    /// The newest epoch this registry knows.
    pub fn current_epoch(&self) -> u64 {
        self.epochs.iter().map(|e| e.epoch).max().unwrap_or(0)
    }

    pub fn epochs(&self) -> &[EpochStart] {
        &self.epochs
    }

    pub fn epoch_start(&self, epoch: u64) -> Option<&EpochStart> {
        self.epochs.iter().find(|e| e.epoch == epoch)
    }

    /// Make `device` the primary of a new epoch (current + 1) whose log
    /// continues after `after_seq`; every other primary becomes a node.
    /// Returns the new epoch. Only ever called by a local action of the
    /// owner on `device` (BMD-19, BMD-20).
    pub fn promote(&mut self, device: &DeviceId, after_seq: u64) -> Result<u64, EnrollmentError> {
        self.active(device)?;
        let epoch = self.current_epoch() + 1;
        for record in self.devices.values_mut() {
            record.role = if record.enrollment.device == *device {
                Role::Primary { epoch }
            } else {
                Role::Node {
                    replica: record.enrollment.holds_replica,
                }
            };
        }
        self.epochs.push(EpochStart {
            epoch,
            primary: device.clone(),
            after_seq,
        });
        Ok(epoch)
    }

    /// Take everything a newer copy of the registry knows (a node's snapshot
    /// meeting the primary's): roles and epochs from whichever copy has the
    /// newer epoch, enrollments by revision, revocations never undone.
    pub fn merge(&mut self, other: &DeviceRegistry) {
        if other.owner != self.owner || other.owner_key != self.owner_key {
            return;
        }
        let other_newer = other.current_epoch() > self.current_epoch();
        for (id, theirs) in &other.devices {
            match self.devices.get_mut(id) {
                None => {
                    self.devices.insert(id.clone(), theirs.clone());
                }
                Some(ours) => {
                    if theirs.enrollment.revision > ours.enrollment.revision
                        && theirs.enrollment.verify(&self.owner_key).is_ok()
                    {
                        ours.enrollment = theirs.enrollment.clone();
                    }
                    ours.revoked |= theirs.revoked;
                    if other_newer {
                        ours.role = theirs.role;
                        if theirs.address.is_some() {
                            ours.address = theirs.address.clone();
                        }
                    }
                }
            }
        }
        for start in &other.epochs {
            if self.epoch_start(start.epoch).is_none() {
                self.epochs.push(start.clone());
            }
        }
        self.epochs.sort_by_key(|e| e.epoch);
    }

    fn check_owner(&self, enrollment: &Enrollment) -> Result<(), EnrollmentError> {
        if enrollment.owner != self.owner {
            return Err(EnrollmentError::WrongOwner {
                expected: self.owner.clone(),
                got: enrollment.owner.clone(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) struct Fixture {
        pub owner: AgeIdentity,
        pub primary: AgeIdentity,
        pub node: AgeIdentity,
        pub registry: DeviceRegistry,
    }

    pub(crate) fn enrollment(owner: &AgeIdentity, id: &str, key: &AgeIdentity) -> Enrollment {
        Enrollment::new(
            "alice",
            DeviceId::new(id),
            key.verifying_key_bytes(),
            Platform::Windows,
            false,
        )
        .sign(owner)
    }

    pub(crate) fn fixture() -> Fixture {
        let owner = AgeIdentity::generate();
        let primary = AgeIdentity::generate();
        let node = AgeIdentity::generate();
        let registry = DeviceRegistry::bootstrap(
            owner.verifying_key_bytes(),
            enrollment(&owner, "linux-box", &primary),
            None,
        )
        .unwrap();
        Fixture {
            owner,
            primary,
            node,
            registry,
        }
    }

    #[test]
    fn a_signed_and_approved_enrollment_is_admitted_as_a_node_with_no_grants() {
        let mut fx = fixture();
        let e = enrollment(&fx.owner, "pc-windows", &fx.node);
        let approval = EnrollmentApproval::sign(DeviceId::new("linux-box"), &fx.primary, &e);
        let record = fx.registry.admit(e, &approval).unwrap();
        assert_eq!(record.role, Role::Node { replica: false });
        assert!(record.enrollment.granted.is_empty());
        assert!(fx.registry.active(&DeviceId::new("pc-windows")).is_ok());
    }

    #[test]
    fn an_enrollment_without_a_valid_owner_signature_is_refused() {
        let mut fx = fixture();
        let stranger = AgeIdentity::generate();
        let forged = enrollment(&stranger, "pc-windows", &fx.node);
        let approval = EnrollmentApproval::sign(DeviceId::new("linux-box"), &fx.primary, &forged);
        assert_eq!(
            fx.registry.admit(forged, &approval).unwrap_err(),
            EnrollmentError::BadOwnerSignature
        );
        // Tampering after signing breaks it too.
        let mut tampered = enrollment(&fx.owner, "pc-windows", &fx.node);
        tampered.granted.push(CapabilityGrant {
            capability: "system.run".into(),
            scope: GrantScope::Any,
            needs_approval: false,
        });
        let approval = EnrollmentApproval::sign(DeviceId::new("linux-box"), &fx.primary, &tampered);
        assert_eq!(
            fx.registry.admit(tampered, &approval).unwrap_err(),
            EnrollmentError::BadOwnerSignature
        );
        assert!(fx.registry.get(&DeviceId::new("pc-windows")).is_none());
    }

    #[test]
    fn an_enrollment_without_approval_from_a_registered_device_is_refused() {
        let mut fx = fixture();
        let e = enrollment(&fx.owner, "pc-windows", &fx.node);
        // Self-approval by the newcomer.
        let own = EnrollmentApproval::sign(DeviceId::new("pc-windows"), &fx.node, &e);
        assert!(matches!(
            fx.registry.admit(e.clone(), &own).unwrap_err(),
            EnrollmentError::UnknownApprover(_)
        ));
        // A registered id, but signed with another key.
        let wrong_key = EnrollmentApproval::sign(DeviceId::new("linux-box"), &fx.node, &e);
        assert_eq!(
            fx.registry.admit(e.clone(), &wrong_key).unwrap_err(),
            EnrollmentError::BadApproval
        );
        // An approval for another enrollment.
        let other = enrollment(&fx.owner, "laptop", &AgeIdentity::generate());
        let replayed = EnrollmentApproval::sign(DeviceId::new("linux-box"), &fx.primary, &other);
        assert_eq!(
            fx.registry.admit(e, &replayed).unwrap_err(),
            EnrollmentError::BadApproval
        );
        assert!(fx.registry.get(&DeviceId::new("pc-windows")).is_none());
    }

    #[test]
    fn grants_change_only_through_a_newer_owner_signed_revision() {
        let mut fx = fixture();
        let e = enrollment(&fx.owner, "pc-windows", &fx.node);
        let approval = EnrollmentApproval::sign(DeviceId::new("linux-box"), &fx.primary, &e);
        fx.registry.admit(e.clone(), &approval).unwrap();

        let mut granted = e.clone();
        granted.granted.push(CapabilityGrant {
            capability: "ui.act".into(),
            scope: GrantScope::Apps(vec!["blender.exe".into()]),
            needs_approval: true,
        });
        granted.revision = 1;
        let granted = granted.sign(&fx.owner);
        fx.registry.update(granted.clone()).unwrap();
        assert!(fx
            .registry
            .get(&DeviceId::new("pc-windows"))
            .unwrap()
            .enrollment
            .grant("ui.act")
            .is_some());
        // Replaying the old revision cannot remove the approval requirement.
        assert!(matches!(
            fx.registry.update(e.sign(&fx.owner)).unwrap_err(),
            EnrollmentError::StaleRevision { .. }
        ));
    }

    #[test]
    fn revoking_returns_the_secrets_the_device_kept() {
        let mut fx = fixture();
        let e = enrollment(&fx.owner, "pc-windows", &fx.node);
        let approval = EnrollmentApproval::sign(DeviceId::new("linux-box"), &fx.primary, &e);
        fx.registry.admit(e.clone(), &approval).unwrap();
        let grant = SecretGrant {
            secret: "anthropic_api_key".into(),
            device: DeviceId::new("pc-windows"),
            granted_at: 1,
        };
        fx.registry
            .active_mut(&DeviceId::new("pc-windows"))
            .unwrap()
            .secret_grants
            .push(grant.clone());
        assert_eq!(
            fx.registry.revoke(&DeviceId::new("pc-windows")).unwrap(),
            vec![grant]
        );
        assert!(matches!(
            fx.registry.active(&DeviceId::new("pc-windows")),
            Err(EnrollmentError::Revoked(_))
        ));
        // Re-admission of a revoked id is refused.
        assert!(matches!(
            fx.registry.admit(e, &approval).unwrap_err(),
            EnrollmentError::Revoked(_)
        ));
    }

    #[test]
    fn scopes_match_apps_by_name_and_paths_by_component() {
        let apps = GrantScope::Apps(vec!["Blender.exe".into()]);
        assert!(apps.allows_app(r"C:\Program Files\Blender\blender.exe"));
        assert!(!apps.allows_app("notepad.exe"));
        let paths = GrantScope::Paths(vec!["/data".into()]);
        assert!(paths.allows_path(std::path::Path::new("/data/x")));
        assert!(!paths.allows_path(std::path::Path::new("/data-other/x")));
        assert!(!apps.allows_path(std::path::Path::new("/data")));
    }

    #[test]
    fn the_registry_round_trips_through_json() {
        let fx = fixture();
        let json = serde_json::to_string(&fx.registry).unwrap();
        let back: DeviceRegistry = serde_json::from_str(&json).unwrap();
        assert_eq!(back, fx.registry);
        assert_eq!(back.primary().unwrap().1, 1);
    }
}

#[cfg(test)]
mod promotion_tests {
    use super::tests::{enrollment, fixture};
    use super::*;

    #[test]
    fn promotion_moves_the_primary_role_and_grows_the_epoch() {
        let mut fx = fixture();
        let e = enrollment(&fx.owner, "pc-windows", &fx.node);
        let approval = EnrollmentApproval::sign(DeviceId::new("linux-box"), &fx.primary, &e);
        fx.registry.admit(e, &approval).unwrap();
        assert_eq!(fx.registry.current_epoch(), 1);

        assert_eq!(
            fx.registry
                .promote(&DeviceId::new("pc-windows"), 42)
                .unwrap(),
            2
        );
        let (primary, epoch) = fx.registry.primary().unwrap();
        assert_eq!(primary.enrollment.device, DeviceId::new("pc-windows"));
        assert_eq!(epoch, 2);
        assert!(matches!(
            fx.registry.get(&DeviceId::new("linux-box")).unwrap().role,
            Role::Node { .. }
        ));
        assert_eq!(fx.registry.epoch_start(2).unwrap().after_seq, 42);

        // The owner can promote the old one back; the epoch grows again.
        assert_eq!(
            fx.registry
                .promote(&DeviceId::new("linux-box"), 50)
                .unwrap(),
            3
        );
        assert_eq!(fx.registry.primary().unwrap().1, 3);
    }

    #[test]
    fn a_revoked_device_cannot_be_promoted() {
        let mut fx = fixture();
        let e = enrollment(&fx.owner, "pc-windows", &fx.node);
        let approval = EnrollmentApproval::sign(DeviceId::new("linux-box"), &fx.primary, &e);
        fx.registry.admit(e, &approval).unwrap();
        fx.registry.revoke(&DeviceId::new("pc-windows")).unwrap();
        assert!(fx
            .registry
            .promote(&DeviceId::new("pc-windows"), 0)
            .is_err());
    }

    #[test]
    fn merging_takes_the_newer_epoch_and_never_undoes_a_revocation() {
        let mut fx = fixture();
        let e = enrollment(&fx.owner, "pc-windows", &fx.node);
        let approval = EnrollmentApproval::sign(DeviceId::new("linux-box"), &fx.primary, &e);
        fx.registry.admit(e, &approval).unwrap();
        let mut promoted = fx.registry.clone();
        promoted.promote(&DeviceId::new("pc-windows"), 9).unwrap();
        let mut stale = fx.registry.clone();
        stale.revoke(&DeviceId::new("pc-windows")).unwrap();
        stale.merge(&promoted);
        assert_eq!(stale.current_epoch(), 2);
        assert!(stale.get(&DeviceId::new("pc-windows")).unwrap().revoked);
    }
}
