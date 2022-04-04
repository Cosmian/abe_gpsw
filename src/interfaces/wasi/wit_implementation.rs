use abe::*;

use super::wit_generation;

cosmian_wit_bindgen_rust::export!("abe.wit");
struct Abe;

fn attributes_to_wit_attributes(attributes: Vec<Attribute>) -> Vec<wit_generation::Attribute> {
    attributes
        .iter()
        .map(|e| wit_generation::Attribute {
            axis_name: e.axis_name.clone(),
            attribute: e.attribute.clone(),
        })
        .collect::<Vec<_>>()
}

impl abe::Abe for Abe {
    fn generate_master_key(nb_revocation: u64, policy: Policy) -> Result<MasterKey, String> {
        let mk = wit_generation::generate_master_key(
            nb_revocation as usize,
            wit_generation::Policy {
                primary_axis: wit_generation::PolicyAxis {
                    name: policy.primary_axis.name,
                    attributes: policy.primary_axis.attributes,
                    hierarchical: policy.primary_axis.hierarchical,
                },
                secondary_axis: wit_generation::PolicyAxis {
                    name: policy.secondary_axis.name,
                    attributes: policy.secondary_axis.attributes,
                    hierarchical: policy.secondary_axis.hierarchical,
                },
            },
        );
        match mk {
            Ok(mk) => Ok(MasterKey {
                private_key: mk.private_key,
                public_key: mk.public_key,
                delegation_key: mk.delegation_key,
                policy_serialized: mk.policy_serialized,
            }),
            Err(_) => Err("failed generating master key".to_string()),
        }
    }

    fn generate_user_decryption_key(
        master_private_key: Vec<u8>,
        access_policy: Option<String>,
        policy: Vec<u8>,
    ) -> Result<String, String> {
        wit_generation::generate_user_decryption_key(master_private_key, access_policy, policy)
    }

    fn create_encryption_cache(master_public_key: Vec<u8>, policy: Vec<u8>) -> Result<i32, String> {
        wit_generation::create_encryption_cache(master_public_key, policy)
    }

    fn destroy_encryption_cache(cache_handle: i32) -> Result<(), String> {
        wit_generation::destroy_encryption_cache(cache_handle)
    }

    fn encrypt(
        plaintext: String,
        master_public_key: Vec<u8>,
        attributes: Vec<Attribute>,
        policy: Vec<u8>,
        uid: Vec<u8>,
    ) -> Result<Vec<u8>, String> {
        wit_generation::encrypt(
            plaintext,
            master_public_key,
            attributes_to_wit_attributes(attributes),
            policy,
            uid,
        )
    }

    fn encrypt_hybrid_header(
        attributes: Vec<Attribute>,
        cache_handle: i32,
        uid: Vec<u8>,
    ) -> Result<EncryptedHeader, String> {
        let encrypted_header = wit_generation::encrypt_hybrid_header(
            attributes_to_wit_attributes(attributes),
            cache_handle,
            uid,
        );
        match encrypted_header {
            Ok(enc) => Ok(EncryptedHeader {
                symmetric_key: enc.symmetric_key,
                encrypted_header_bytes: enc.encrypted_header_bytes,
            }),
            Err(_) => Err("failed encrypt hybrid header".to_string()),
        }
    }

    fn encrypt_hybrid_block(
        plaintext: String,
        symmetric_key: Vec<u8>,
        uid: Vec<u8>,
        block_number: u64,
    ) -> Result<Vec<u8>, String> {
        wit_generation::encrypt_hybrid_block(plaintext, symmetric_key, uid, block_number)
    }

    fn decrypt(user_decryption_key: String, encrypted_data: Vec<u8>) -> Result<String, String> {
        wit_generation::decrypt(user_decryption_key, encrypted_data)
    }

    fn create_decryption_cache(user_decryption_key: Vec<u8>) -> Result<i32, String> {
        wit_generation::create_decryption_cache(user_decryption_key)
    }

    fn destroy_decryption_cache(cache_handle: i32) -> Result<(), String> {
        wit_generation::destroy_decryption_cache(cache_handle)
    }

    fn decrypt_hybrid_header(cache_handle: i32, encrypted_data: Vec<u8>) -> Result<String, String> {
        wit_generation::decrypt_hybrid_header(cache_handle, encrypted_data)
    }

    fn decrypt_hybrid_block(
        ciphertext: Vec<u8>,
        symmetric_key: Vec<u8>,
        uid: Vec<u8>,
        block_number: u64,
    ) -> Result<Vec<u8>, String> {
        wit_generation::decrypt_hybrid_block(ciphertext, symmetric_key, uid, block_number)
    }

    fn delegate_user_decryption_key(
        delegation_key: Vec<u8>,
        user_decryption_key: String,
        policy: Vec<u8>,
        access_policy: Option<String>,
    ) -> Result<String, String> {
        wit_generation::delegate_user_decryption_key(
            delegation_key,
            user_decryption_key,
            policy,
            access_policy,
        )
    }

    fn rotate_attributes(policy: Vec<u8>, attributes: Vec<Attribute>) -> Result<Vec<u8>, String> {
        let _attributes = attributes
            .iter()
            .map(|e| wit_generation::Attribute {
                axis_name: e.axis_name.clone(),
                attribute: e.attribute.clone(),
            })
            .collect::<Vec<_>>();
        wit_generation::rotate_attributes(policy, _attributes)
    }
}
