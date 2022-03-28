use abe::*;

use super::wit_generation;

wit_bindgen_rust::export!("abe.wit");
struct Abe;

impl abe::Abe for Abe {
    fn generate_master_key(nb_revocation: u64, policy: Policy) -> Result<MasterKey, String> {
        let mk = wit_generation::generate_master_key(
            nb_revocation as usize,
            wit_generation::Policy {
                primary_axis: wit_generation::PolicyAxis {
                    name: policy.primary_axis.name,
                    attributes: policy.primary_axis.attributes,
                    hierarchical: false,
                },
                secondary_axis: wit_generation::PolicyAxis {
                    name: policy.secondary_axis.name,
                    attributes: policy.secondary_axis.attributes,
                    hierarchical: true,
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

    fn encrypt(
        plaintext: String,
        master_public_key: Vec<u8>,
        attributes: Vec<Attribute>,
        policy: Vec<u8>,
    ) -> Result<Vec<u8>, String> {
        let attributes = attributes
            .iter()
            .map(|e| wit_generation::Attribute {
                axis_name: e.axis_name.clone(),
                attribute: e.attribute.clone(),
            })
            .collect::<Vec<_>>();
        wit_generation::encrypt(plaintext, master_public_key, attributes, policy)
    }

    fn decrypt(user_decryption_key: String, encrypted_data: Vec<u8>) -> Result<String, String> {
        wit_generation::decrypt(user_decryption_key, encrypted_data)
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
