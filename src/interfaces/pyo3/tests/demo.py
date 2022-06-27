import json
import abe_gpsw


# Declare 2 ABE policy axis:
policy_axis_json = [
    {
        "name": "Security Level",
        "attributes": [
            "Protected",
            "Low Secret",
            "Medium Secret",
            "High Secret",
            "Top Secret"
        ],
        "hierarchical": True
    },
    {
        "name": "Department",
        "attributes": [
            "R&D",
            "HR",
            "MKG",
            "FIN"
        ],
        "hierarchical": False
    }
]

policy_axis = bytes(json.dumps(policy_axis_json), 'utf-8')

policy = abe_gpsw.generate_policy(
    policy_axis_bytes=policy_axis, max_attribute_value=100)

master_keys = abe_gpsw.generate_master_keys(policy)

top_secret_mkg_fin_user = abe_gpsw.generate_user_private_key(
    master_keys[0], "Security Level::Top Secret && (Department::MKG || Department::FIN)", policy)

medium_secret_mkg_user = abe_gpsw.generate_user_private_key(
    master_keys[0], "Security Level::Medium Secret && Department::MKG", policy)


# Encryption
metadata_json = {"uid": [0, 0, 0, 0, 0, 0, 0, 1]}
metadata = bytes(json.dumps(metadata_json), 'utf-8')
plaintext = "My secret data"
plaintext_bytes = bytes(plaintext, 'utf-8')

# Encrypt with different ABE policies
low_secret_mkg_data = abe_gpsw.encrypt(metadata, policy, bytes(json.dumps(
    ['Security Level::Low Secret', 'Department::MKG']), 'utf8'), master_keys[1], plaintext_bytes)
top_secret_mkg_data = abe_gpsw.encrypt(metadata, policy, bytes(json.dumps(
    ['Security Level::Top Secret', 'Department::MKG']), 'utf8'), master_keys[1], plaintext_bytes)
low_secret_fin_data = abe_gpsw.encrypt(metadata, policy, bytes(json.dumps(
    ['Security Level::Low Secret', 'Department::FIN']), 'utf8'), master_keys[1], plaintext_bytes)

# The medium secret marketing user can successfully decrypt a low security marketing message:
cleartext = abe_gpsw.decrypt(medium_secret_mkg_user, low_secret_mkg_data)
assert(str(bytes(cleartext), "utf-8") == plaintext)

# .. however it can neither decrypt a marketing message with higher security:
try:
    cleartext = abe_gpsw.decrypt(
        medium_secret_mkg_user, top_secret_mkg_data)
except Exception as ex:
    print(f"As expected, user cannot decrypt this message: {ex}")

try:
    cleartext = abe_gpsw.decrypt(
        medium_secret_mkg_user, low_secret_fin_data)
except Exception as ex:
    print(f"As expected, user cannot decrypt this message: {ex}")

# The "top secret-marketing-financial" user can decrypt messages from the marketing department
# OR the financial department that have a security level of Top Secret or below
# As expected, the top secret marketing financial user can successfully decrypt all messages
cleartext = abe_gpsw.decrypt(top_secret_mkg_fin_user, low_secret_mkg_data)
assert(str(bytes(cleartext), "utf-8") == plaintext)

cleartext = abe_gpsw.decrypt(top_secret_mkg_fin_user, top_secret_mkg_data)
assert(str(bytes(cleartext), "utf-8") == plaintext)

cleartext = abe_gpsw.decrypt(top_secret_mkg_fin_user, low_secret_fin_data)
assert(str(bytes(cleartext), "utf-8") == plaintext)

# Rotation of Policy attributes
# At anytime, Policy attributes can be rotated.
# When that happens future encryption of data for a "rotated" attribute cannot
# be decrypted with user decryption keys which are not "refreshed" for that
# attribute. Let us rotate the Security Level Low Secret
new_policy = abe_gpsw.rotate_attributes(bytes(json.dumps(
    ['Security Level::Low Secret']), 'utf8'), policy)
# print(new_policy)
new_low_secret_mkg_data = abe_gpsw.encrypt(metadata, new_policy, bytes(json.dumps(
    ['Security Level::Low Secret', 'Department::MKG']), 'utf8'), master_keys[1], plaintext_bytes)

# The medium secret user cannot decrypt the new message until its key is refreshed
try:
    cleartext = abe_gpsw.decrypt(
        medium_secret_mkg_user, new_low_secret_mkg_data)
except Exception as ex:
    print(f"As expected, user cannot decrypt this message: {ex}")

# Refresh medium secret key
new_medium_secret_mkg_user = abe_gpsw.generate_user_private_key(
    master_keys[0], "Security Level::Medium Secret && Department::MKG", new_policy)

# New messages can now be decrypted
cleartext = abe_gpsw.decrypt(
    new_medium_secret_mkg_user, new_low_secret_mkg_data)
assert(str(bytes(cleartext), "utf-8") == plaintext)

print("Before the rotation of attribute Security Level::Low Secret")
print(json.loads(str(bytes(policy), "utf-8")))
print("After attributes rotation")
print(json.loads(str(bytes(new_policy), "utf-8")))

# Generation delegated key
super_delegate = abe_gpsw.generate_delegated_key(
    delegation_key_bytes=master_keys[2],
    user_decryption_key_bytes=top_secret_mkg_fin_user,
    access_policy_str="(Department::FIN || Department::MKG) && Security Level::Medium Secret",
    policy_bytes=policy
)
