use pyo3::{exceptions::PyTypeError, prelude::*};

use crate::{
    core::{
        bilinear_map::bls12_381::Bls12_381,
        gpsw::{scheme::GpswMasterPrivateKey, AsBytes, Gpsw},
        Engine,
    },
    interfaces::policy::{AccessPolicy, Attribute, Policy, PolicyAxis},
};

/// Generate the master authority keys for supplied Policy
///
///  - `policy_bytes` : Policy to use to generate the keys (JSON serialized)
#[pyfunction]
pub fn generate_master_keys(policy_bytes: Vec<u8>) -> PyResult<(Vec<u8>, Vec<u8>)> {
    let policy: Policy = serde_json::from_slice(policy_bytes.as_slice())
        .map_err(|e| PyTypeError::new_err(format!("Policy deserialization failed: {e}")))?;

    //
    // Setup CoverCrypt
    let (master_private_key, master_public_key, _) =
        Engine::<Gpsw<Bls12_381>>::new().generate_master_key(&policy)?;

    Ok((
        master_private_key.try_into_bytes()?,
        master_public_key.try_into_bytes()?,
    ))
}

/// Generate a user private key.
///
/// - `master_private_key_bytes`    : master secret key
/// - `access_policy_str`           : user access policy
/// - `policy_bytes`                : global policy
#[pyfunction]
pub fn generate_user_private_key(
    master_private_key_bytes: Vec<u8>,
    access_policy_str: String,
    policy_bytes: Vec<u8>,
) -> PyResult<Vec<u8>> {
    let master_private_key =
        GpswMasterPrivateKey::<Bls12_381>::try_from_bytes(&master_private_key_bytes)?;
    let policy = serde_json::from_slice(&policy_bytes)
        .map_err(|e| PyTypeError::new_err(format!("Policy deserialization failed: {e}")))?;
    let access_policy = AccessPolicy::from_boolean_expression(&access_policy_str)?;

    let user_key = Engine::<Gpsw<Bls12_381>>::new().generate_user_key(
        &policy,
        &master_private_key,
        &access_policy,
    )?;

    Ok(user_key.try_into_bytes()?)
}

/// Generate ABE policy from axis given in serialized JSON
///
/// - `policy_axis_bytes`: as many axis as needed
/// - `max_attribute_value`: maximum number of attributes that can be used in
///   policy
#[pyfunction]
pub fn generate_policy(
    policy_axis_bytes: Vec<u8>,
    max_attribute_value: usize,
) -> PyResult<Vec<u8>> {
    let policy_axis: Vec<PolicyAxis> = serde_json::from_slice(&policy_axis_bytes)
        .map_err(|e| PyTypeError::new_err(format!("Policy Axis deserialization failed: {e}")))?;
    let mut policy = Policy::new(max_attribute_value);
    for axis in &policy_axis {
        let attrs = axis
            .attributes
            .iter()
            .map(std::ops::Deref::deref)
            .collect::<Vec<_>>();
        policy = policy.add_axis(&axis.name, &attrs, axis.hierarchical)?;
    }
    let policy_bytes = serde_json::to_vec(&policy)
        .map_err(|e| PyTypeError::new_err(format!("Error serializing policy: {e}")))?;

    Ok(policy_bytes)
}

#[pyfunction]
pub fn rotate_attributes(attributes_bytes: Vec<u8>, policy_bytes: Vec<u8>) -> PyResult<Vec<u8>> {
    let attributes: Vec<Attribute> = serde_json::from_slice(&attributes_bytes)
        .map_err(|e| PyTypeError::new_err(format!("Error deserializing attributes: {e}")))?;
    let mut policy: Policy = serde_json::from_slice(&policy_bytes)
        .map_err(|e| PyTypeError::new_err(format!("Error deserializing policy: {e}")))?;

    for attr in &attributes {
        policy.rotate(attr)?;
    }
    serde_json::to_vec(&policy)
        .map_err(|e| PyTypeError::new_err(format!("Error serializing policy: {e}")))
}
