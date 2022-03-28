from abc import abstractmethod
import ctypes
from dataclasses import dataclass
from typing import Any, Generic, List, Optional, Tuple, TypeVar, Union, cast
import wasmtime

try:
    from typing import Protocol
except ImportError:
    class Protocol: # type: ignore
        pass

T = TypeVar('T')

def _clamp(i: int, min: int, max: int) -> int:
    if i < min or i > max:
        raise OverflowError(f'must be between {min} and {max}')
    return i

def _store(ty: Any, mem: wasmtime.Memory, store: wasmtime.Storelike, base: int, offset: int, val: Any) -> None:
    ptr = (base & 0xffffffff) + offset
    if ptr + ctypes.sizeof(ty) > mem.data_len(store):
        raise IndexError('out-of-bounds store')
    raw_base = mem.data_ptr(store)
    c_ptr = ctypes.POINTER(ty)(
        ty.from_address(ctypes.addressof(raw_base.contents) + ptr)
    )
    c_ptr[0] = val

def _load(ty: Any, mem: wasmtime.Memory, store: wasmtime.Storelike, base: int, offset: int) -> Any:
    ptr = (base & 0xffffffff) + offset
    if ptr + ctypes.sizeof(ty) > mem.data_len(store):
        raise IndexError('out-of-bounds store')
    raw_base = mem.data_ptr(store)
    c_ptr = ctypes.POINTER(ty)(
        ty.from_address(ctypes.addressof(raw_base.contents) + ptr)
    )
    return c_ptr[0]

@dataclass
class Ok(Generic[T]):
    value: T
E = TypeVar('E')
@dataclass
class Err(Generic[E]):
    value: E

Expected = Union[Ok[T], Err[E]]

def _decode_utf8(mem: wasmtime.Memory, store: wasmtime.Storelike, ptr: int, len: int) -> str:
    ptr = ptr & 0xffffffff
    len = len & 0xffffffff
    if ptr + len > mem.data_len(store):
        raise IndexError('string out of bounds')
    base = mem.data_ptr(store)
    base = ctypes.POINTER(ctypes.c_ubyte)(
        ctypes.c_ubyte.from_address(ctypes.addressof(base.contents) + ptr)
    )
    return ctypes.string_at(base, len).decode('utf-8')

def _encode_utf8(val: str, realloc: wasmtime.Func, mem: wasmtime.Memory, store: wasmtime.Storelike) -> Tuple[int, int]:
    bytes = val.encode('utf8')
    ptr = realloc(store, 0, 0, 1, len(bytes))
    assert(isinstance(ptr, int))
    ptr = ptr & 0xffffffff
    if ptr + len(bytes) > mem.data_len(store):
        raise IndexError('string out of bounds')
    base = mem.data_ptr(store)
    base = ctypes.POINTER(ctypes.c_ubyte)(
        ctypes.c_ubyte.from_address(ctypes.addressof(base.contents) + ptr)
    )
    ctypes.memmove(base, bytes, len(bytes))
    return (ptr, len(bytes))

def _list_canon_lift(ptr: int, len: int, size: int, ty: Any, mem: wasmtime.Memory ,store: wasmtime.Storelike) -> Any:
    ptr = ptr & 0xffffffff
    len = len & 0xffffffff
    if ptr + len * size > mem.data_len(store):
        raise IndexError('list out of bounds')
    raw_base = mem.data_ptr(store)
    base = ctypes.POINTER(ty)(
        ty.from_address(ctypes.addressof(raw_base.contents) + ptr)
    )
    if ty == ctypes.c_uint8:
        return ctypes.string_at(base, len)
    return base[:len]

def _list_canon_lower(list: Any, ty: Any, size: int, align: int, realloc: wasmtime.Func, mem: wasmtime.Memory, store: wasmtime.Storelike) -> Tuple[int, int]:
    total_size = size * len(list)
    ptr = realloc(store, 0, 0, align, total_size)
    assert(isinstance(ptr, int))
    ptr = ptr & 0xffffffff
    if ptr + total_size > mem.data_len(store):
        raise IndexError('list realloc return of bounds')
    raw_base = mem.data_ptr(store)
    base = ctypes.POINTER(ty)(
        ty.from_address(ctypes.addressof(raw_base.contents) + ptr)
    )
    for i, val in enumerate(list):
        base[i] = val
    return (ptr, len(list))
# This is a generated file by witgen (https://github.com/bnjjj/witgen), please do not edit yourself, you can generate a new one thanks to cargo witgen generate command
# This struct only provides a visual way to display attributes arguments
@dataclass
class Attribute:
    axis_name: str
    attribute: str

# Regroup private, public and delegation keys in same struct
@dataclass
class MasterKey:
    private_key: bytes
    public_key: bytes
    delegation_key: bytes
    policy_serialized: bytes

@dataclass
class PolicyAxis:
    name: str
    attributes: List[str]
    hierarchical: bool

# This struct only provides a visual way to display policy arguments
@dataclass
class Policy:
    primary_axis: PolicyAxis
    secondary_axis: PolicyAxis

class Abe:
    instance: wasmtime.Instance
    _canonical_abi_free: wasmtime.Func
    _canonical_abi_realloc: wasmtime.Func
    _decrypt: wasmtime.Func
    _delegate_user_decryption_key: wasmtime.Func
    _encrypt: wasmtime.Func
    _generate_master_key: wasmtime.Func
    _generate_user_decryption_key: wasmtime.Func
    _memory: wasmtime.Memory
    _rotate_attributes: wasmtime.Func
    def __init__(self, store: wasmtime.Store, linker: wasmtime.Linker, module: wasmtime.Module):
        self.instance = linker.instantiate(store, module)
        exports = self.instance.exports(store)
        
        canonical_abi_free = exports['canonical_abi_free']
        assert(isinstance(canonical_abi_free, wasmtime.Func))
        self._canonical_abi_free = canonical_abi_free
        
        canonical_abi_realloc = exports['canonical_abi_realloc']
        assert(isinstance(canonical_abi_realloc, wasmtime.Func))
        self._canonical_abi_realloc = canonical_abi_realloc
        
        decrypt = exports['decrypt']
        assert(isinstance(decrypt, wasmtime.Func))
        self._decrypt = decrypt
        
        delegate_user_decryption_key = exports['delegate_user_decryption_key']
        assert(isinstance(delegate_user_decryption_key, wasmtime.Func))
        self._delegate_user_decryption_key = delegate_user_decryption_key
        
        encrypt = exports['encrypt']
        assert(isinstance(encrypt, wasmtime.Func))
        self._encrypt = encrypt
        
        generate_master_key = exports['generate_master_key']
        assert(isinstance(generate_master_key, wasmtime.Func))
        self._generate_master_key = generate_master_key
        
        generate_user_decryption_key = exports['generate_user_decryption_key']
        assert(isinstance(generate_user_decryption_key, wasmtime.Func))
        self._generate_user_decryption_key = generate_user_decryption_key
        
        memory = exports['memory']
        assert(isinstance(memory, wasmtime.Memory))
        self._memory = memory
        
        rotate_attributes = exports['rotate_attributes']
        assert(isinstance(rotate_attributes, wasmtime.Func))
        self._rotate_attributes = rotate_attributes
    def generate_user_decryption_key(self, caller: wasmtime.Store, master_private_key: bytes, access_policy: Optional[str], policy: bytes) -> Expected[str, str]:
        memory = self._memory;
        realloc = self._canonical_abi_realloc
        free = self._canonical_abi_free
        ptr, len0 = _list_canon_lower(master_private_key, ctypes.c_uint8, 1, 1, realloc, memory, caller)
        if access_policy is None:
            variant = 0
            variant4 = 0
            variant5 = 0
        else:
            payload1 = access_policy
            ptr2, len3 = _encode_utf8(payload1, realloc, memory, caller)
            variant = 1
            variant4 = ptr2
            variant5 = len3
        ptr6, len7 = _list_canon_lower(policy, ctypes.c_uint8, 1, 1, realloc, memory, caller)
        ret = self._generate_user_decryption_key(caller, ptr, len0, variant, variant4, variant5, ptr6, len7)
        assert(isinstance(ret, int))
        load = _load(ctypes.c_int32, memory, caller, ret, 0)
        load8 = _load(ctypes.c_int32, memory, caller, ret, 8)
        load9 = _load(ctypes.c_int32, memory, caller, ret, 16)
        variant15: Expected[str, str]
        if load == 0:
            ptr10 = load8
            len11 = load9
            list = _decode_utf8(memory, caller, ptr10, len11)
            free(caller, ptr10, len11, 1)
            variant15 = Ok(list)
        elif load == 1:
            ptr12 = load8
            len13 = load9
            list14 = _decode_utf8(memory, caller, ptr12, len13)
            free(caller, ptr12, len13, 1)
            variant15 = Err(list14)
        else:
            raise TypeError("invalid variant discriminant for expected")
        return variant15
    def encrypt(self, caller: wasmtime.Store, plaintext: str, master_public_key: bytes, attributes: List[Attribute], policy: bytes) -> Expected[bytes, str]:
        memory = self._memory;
        realloc = self._canonical_abi_realloc
        free = self._canonical_abi_free
        ptr, len0 = _encode_utf8(plaintext, realloc, memory, caller)
        ptr1, len2 = _list_canon_lower(master_public_key, ctypes.c_uint8, 1, 1, realloc, memory, caller)
        vec = attributes
        len9 = len(vec)
        result = realloc(caller, 0, 0, 4, len9 * 16)
        assert(isinstance(result, int))
        for i10 in range(0, len9):
            e = vec[i10]
            base3 = result + i10 * 16
            record = e
            field = record.axis_name
            field4 = record.attribute
            ptr5, len6 = _encode_utf8(field, realloc, memory, caller)
            _store(ctypes.c_uint32, memory, caller, base3, 4, len6)
            _store(ctypes.c_uint32, memory, caller, base3, 0, ptr5)
            ptr7, len8 = _encode_utf8(field4, realloc, memory, caller)
            _store(ctypes.c_uint32, memory, caller, base3, 12, len8)
            _store(ctypes.c_uint32, memory, caller, base3, 8, ptr7)
        ptr11, len12 = _list_canon_lower(policy, ctypes.c_uint8, 1, 1, realloc, memory, caller)
        ret = self._encrypt(caller, ptr, len0, ptr1, len2, result, len9, ptr11, len12)
        assert(isinstance(ret, int))
        load = _load(ctypes.c_int32, memory, caller, ret, 0)
        load13 = _load(ctypes.c_int32, memory, caller, ret, 8)
        load14 = _load(ctypes.c_int32, memory, caller, ret, 16)
        variant: Expected[bytes, str]
        if load == 0:
            ptr15 = load13
            len16 = load14
            list = cast(bytes, _list_canon_lift(ptr15, len16, 1, ctypes.c_uint8, memory, caller))
            free(caller, ptr15, len16, 1)
            variant = Ok(list)
        elif load == 1:
            ptr17 = load13
            len18 = load14
            list19 = _decode_utf8(memory, caller, ptr17, len18)
            free(caller, ptr17, len18, 1)
            variant = Err(list19)
        else:
            raise TypeError("invalid variant discriminant for expected")
        return variant
    def delegate_user_decryption_key(self, caller: wasmtime.Store, delegation_key: bytes, user_decryption_key: str, policy: bytes, access_policy: Optional[str]) -> Expected[str, str]:
        memory = self._memory;
        realloc = self._canonical_abi_realloc
        free = self._canonical_abi_free
        ptr, len0 = _list_canon_lower(delegation_key, ctypes.c_uint8, 1, 1, realloc, memory, caller)
        ptr1, len2 = _encode_utf8(user_decryption_key, realloc, memory, caller)
        ptr3, len4 = _list_canon_lower(policy, ctypes.c_uint8, 1, 1, realloc, memory, caller)
        if access_policy is None:
            variant = 0
            variant8 = 0
            variant9 = 0
        else:
            payload5 = access_policy
            ptr6, len7 = _encode_utf8(payload5, realloc, memory, caller)
            variant = 1
            variant8 = ptr6
            variant9 = len7
        ret = self._delegate_user_decryption_key(caller, ptr, len0, ptr1, len2, ptr3, len4, variant, variant8, variant9)
        assert(isinstance(ret, int))
        load = _load(ctypes.c_int32, memory, caller, ret, 0)
        load10 = _load(ctypes.c_int32, memory, caller, ret, 8)
        load11 = _load(ctypes.c_int32, memory, caller, ret, 16)
        variant17: Expected[str, str]
        if load == 0:
            ptr12 = load10
            len13 = load11
            list = _decode_utf8(memory, caller, ptr12, len13)
            free(caller, ptr12, len13, 1)
            variant17 = Ok(list)
        elif load == 1:
            ptr14 = load10
            len15 = load11
            list16 = _decode_utf8(memory, caller, ptr14, len15)
            free(caller, ptr14, len15, 1)
            variant17 = Err(list16)
        else:
            raise TypeError("invalid variant discriminant for expected")
        return variant17
    def generate_master_key(self, caller: wasmtime.Store, nb_revocation: int, policy: Policy) -> Expected[MasterKey, str]:
        memory = self._memory;
        realloc = self._canonical_abi_realloc
        free = self._canonical_abi_free
        record = policy
        field = record.primary_axis
        field0 = record.secondary_axis
        record1 = field
        field2 = record1.name
        field3 = record1.attributes
        field4 = record1.hierarchical
        ptr, len5 = _encode_utf8(field2, realloc, memory, caller)
        vec = field3
        len9 = len(vec)
        result = realloc(caller, 0, 0, 4, len9 * 8)
        assert(isinstance(result, int))
        for i10 in range(0, len9):
            e = vec[i10]
            base6 = result + i10 * 8
            ptr7, len8 = _encode_utf8(e, realloc, memory, caller)
            _store(ctypes.c_uint32, memory, caller, base6, 4, len8)
            _store(ctypes.c_uint32, memory, caller, base6, 0, ptr7)
        record12 = field0
        field13 = record12.name
        field14 = record12.attributes
        field15 = record12.hierarchical
        ptr16, len17 = _encode_utf8(field13, realloc, memory, caller)
        vec22 = field14
        len24 = len(vec22)
        result23 = realloc(caller, 0, 0, 4, len24 * 8)
        assert(isinstance(result23, int))
        for i25 in range(0, len24):
            e18 = vec22[i25]
            base19 = result23 + i25 * 8
            ptr20, len21 = _encode_utf8(e18, realloc, memory, caller)
            _store(ctypes.c_uint32, memory, caller, base19, 4, len21)
            _store(ctypes.c_uint32, memory, caller, base19, 0, ptr20)
        ret = self._generate_master_key(caller, _clamp(nb_revocation, 0, 18446744073709551615), ptr, len5, result, len9, int(field4), ptr16, len17, result23, len24, int(field15))
        assert(isinstance(ret, int))
        load = _load(ctypes.c_int32, memory, caller, ret, 0)
        load28 = _load(ctypes.c_int32, memory, caller, ret, 8)
        load29 = _load(ctypes.c_int32, memory, caller, ret, 16)
        load30 = _load(ctypes.c_int32, memory, caller, ret, 24)
        load31 = _load(ctypes.c_int32, memory, caller, ret, 32)
        load32 = _load(ctypes.c_int32, memory, caller, ret, 40)
        load33 = _load(ctypes.c_int32, memory, caller, ret, 48)
        load34 = _load(ctypes.c_int32, memory, caller, ret, 56)
        load35 = _load(ctypes.c_int32, memory, caller, ret, 64)
        variant: Expected[MasterKey, str]
        if load == 0:
            ptr36 = load28
            len37 = load29
            list = cast(bytes, _list_canon_lift(ptr36, len37, 1, ctypes.c_uint8, memory, caller))
            free(caller, ptr36, len37, 1)
            ptr38 = load30
            len39 = load31
            list40 = cast(bytes, _list_canon_lift(ptr38, len39, 1, ctypes.c_uint8, memory, caller))
            free(caller, ptr38, len39, 1)
            ptr41 = load32
            len42 = load33
            list43 = cast(bytes, _list_canon_lift(ptr41, len42, 1, ctypes.c_uint8, memory, caller))
            free(caller, ptr41, len42, 1)
            ptr44 = load34
            len45 = load35
            list46 = cast(bytes, _list_canon_lift(ptr44, len45, 1, ctypes.c_uint8, memory, caller))
            free(caller, ptr44, len45, 1)
            variant = Ok(MasterKey(list, list40, list43, list46))
        elif load == 1:
            ptr47 = load28
            len48 = load29
            list49 = _decode_utf8(memory, caller, ptr47, len48)
            free(caller, ptr47, len48, 1)
            variant = Err(list49)
        else:
            raise TypeError("invalid variant discriminant for expected")
        return variant
    def decrypt(self, caller: wasmtime.Store, user_decryption_key: str, encrypted_data: bytes) -> Expected[str, str]:
        memory = self._memory;
        realloc = self._canonical_abi_realloc
        free = self._canonical_abi_free
        ptr, len0 = _encode_utf8(user_decryption_key, realloc, memory, caller)
        ptr1, len2 = _list_canon_lower(encrypted_data, ctypes.c_uint8, 1, 1, realloc, memory, caller)
        ret = self._decrypt(caller, ptr, len0, ptr1, len2)
        assert(isinstance(ret, int))
        load = _load(ctypes.c_int32, memory, caller, ret, 0)
        load3 = _load(ctypes.c_int32, memory, caller, ret, 8)
        load4 = _load(ctypes.c_int32, memory, caller, ret, 16)
        variant: Expected[str, str]
        if load == 0:
            ptr5 = load3
            len6 = load4
            list = _decode_utf8(memory, caller, ptr5, len6)
            free(caller, ptr5, len6, 1)
            variant = Ok(list)
        elif load == 1:
            ptr7 = load3
            len8 = load4
            list9 = _decode_utf8(memory, caller, ptr7, len8)
            free(caller, ptr7, len8, 1)
            variant = Err(list9)
        else:
            raise TypeError("invalid variant discriminant for expected")
        return variant
    def rotate_attributes(self, caller: wasmtime.Store, policy: bytes, attributes: List[Attribute]) -> Expected[bytes, str]:
        memory = self._memory;
        realloc = self._canonical_abi_realloc
        free = self._canonical_abi_free
        ptr, len0 = _list_canon_lower(policy, ctypes.c_uint8, 1, 1, realloc, memory, caller)
        vec = attributes
        len7 = len(vec)
        result = realloc(caller, 0, 0, 4, len7 * 16)
        assert(isinstance(result, int))
        for i8 in range(0, len7):
            e = vec[i8]
            base1 = result + i8 * 16
            record = e
            field = record.axis_name
            field2 = record.attribute
            ptr3, len4 = _encode_utf8(field, realloc, memory, caller)
            _store(ctypes.c_uint32, memory, caller, base1, 4, len4)
            _store(ctypes.c_uint32, memory, caller, base1, 0, ptr3)
            ptr5, len6 = _encode_utf8(field2, realloc, memory, caller)
            _store(ctypes.c_uint32, memory, caller, base1, 12, len6)
            _store(ctypes.c_uint32, memory, caller, base1, 8, ptr5)
        ret = self._rotate_attributes(caller, ptr, len0, result, len7)
        assert(isinstance(ret, int))
        load = _load(ctypes.c_int32, memory, caller, ret, 0)
        load9 = _load(ctypes.c_int32, memory, caller, ret, 8)
        load10 = _load(ctypes.c_int32, memory, caller, ret, 16)
        variant: Expected[bytes, str]
        if load == 0:
            ptr11 = load9
            len12 = load10
            list = cast(bytes, _list_canon_lift(ptr11, len12, 1, ctypes.c_uint8, memory, caller))
            free(caller, ptr11, len12, 1)
            variant = Ok(list)
        elif load == 1:
            ptr13 = load9
            len14 = load10
            list15 = _decode_utf8(memory, caller, ptr13, len14)
            free(caller, ptr13, len14, 1)
            variant = Err(list15)
        else:
            raise TypeError("invalid variant discriminant for expected")
        return variant
