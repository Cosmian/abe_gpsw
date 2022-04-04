from wasmtime import Linker, Module, Store, WasiConfig

from bindings import Abe, Attribute, Ok, Policy, PolicyAxis

import datetime

store = Store()
wasi_config = WasiConfig()
wasi_config.inherit_stderr()
wasi_config.inherit_stdin()
wasi_config.inherit_stdout()
store.set_wasi(wasi_config)

linker = Linker(store.engine)
linker.define_wasi()

my_module = Module.from_file(
    store.engine, "target/wasm32-wasi/release/abe_gpsw.wasm")
abe = Abe(store, linker, my_module)


def unwrap(wrapped_result):
    """
    If the result is an Ok, return the value, otherwise raise an exception

    :param wrapped_result: The result of a function that returns a wrapped
    object
    :return: A list of strings.
    """
    if isinstance(wrapped_result, Ok):
        return wrapped_result.value
    raise Exception(wrapped_result.value)


entities_axis = PolicyAxis(
    name="Departments",
    attributes=["RnD", "HR", "MKG", "FIN"],
    hierarchical=False
)
security_axis = PolicyAxis(
    name="Security_Level",
    attributes=["level_1", "level_2", "level_3", "level_4", "level_5"],
    hierarchical=True,
)
policy_definition = Policy(
    primary_axis=entities_axis, secondary_axis=security_axis
)

master_key = unwrap(abe.generate_master_key(store, 100, policy_definition))

##
super_delegate = unwrap(
    abe.generate_user_decryption_key(
        store, master_key.private_key, None, master_key.policy_serialized
    )
)
access_policy_mkg = "Departments::MKG && Security_Level::level_1"
user_decryption_key_mkg = abe.delegate_user_decryption_key(
    store,
    master_key.delegation_key,
    super_delegate,
    master_key.policy_serialized,
    access_policy_mkg,
)

##
another_user_decryption_key_mkg = unwrap(
    abe.generate_user_decryption_key(
        store, master_key.private_key, access_policy_mkg, master_key.policy_serialized
    )
)
print(another_user_decryption_key_mkg)

uid = bytes([1, 2, 3, 4, 5, 6, 7, 8])
loops = 10
first_time = datetime.datetime.now()

for i in range(0, loops):
    plaintext = "my confidential data"
    ciphertext = unwrap(
        abe.encrypt(
            store,
            plaintext,
            master_key.public_key,
            [
                Attribute("Departments", "MKG"),
                Attribute("Security_Level", "level_1"),
            ],
            master_key.policy_serialized,
            uid
        )
    )
difference = (datetime.datetime.now() - first_time) / loops
print(difference.total_seconds() * 1000)

print(ciphertext)

cleartext = unwrap(abe.decrypt(
    store, another_user_decryption_key_mkg, ciphertext))
print(cleartext)

assert plaintext == cleartext


loops = 10

cache_handle = unwrap(abe.create_encryption_cache(
    store, master_key.public_key, master_key.policy_serialized))

first_time = datetime.datetime.now()
for i in range(0, loops):
    plaintext = "my confidential data"

    header = unwrap(
        abe.encrypt_hybrid_header(store, [
            Attribute("Departments", "MKG"),
            Attribute("Security_Level", "level_1"),
        ], cache_handle, uid)
    )

    sym_ciphertext = unwrap(abe.encrypt_hybrid_block(
        store, plaintext, header.symmetric_key, uid, 0))

    header_len = (len(header.encrypted_header_bytes)
                  ).to_bytes(4, byteorder='big')
    ciphertext = b"".join(
        [header_len, header.encrypted_header_bytes, sym_ciphertext])

difference = (datetime.datetime.now() - first_time) / loops
print(difference.total_seconds() * 1000)
unwrap(abe.destroy_encryption_cache(store, cache_handle))


print(ciphertext)

cleartext = unwrap(abe.decrypt(
    store, another_user_decryption_key_mkg, ciphertext))
print(cleartext)

assert plaintext == cleartext
