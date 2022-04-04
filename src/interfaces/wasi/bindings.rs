mod abe {
  /// This struct only provides a visual way to display attributes arguments
  #[derive(Clone)]
  pub struct Attribute {
    pub axis_name: String,
    pub attribute: String,
  }
  impl std::fmt::Debug for Attribute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
      f.debug_struct("Attribute").field("axis_name", &self.axis_name).field("attribute", &self.attribute).finish()}
  }
  /// Regroup private, public and delegation keys in same struct
  #[derive(Clone)]
  pub struct MasterKey {
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
    pub delegation_key: Vec<u8>,
    pub policy_serialized: Vec<u8>,
  }
  impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
      f.debug_struct("MasterKey").field("private_key", &self.private_key).field("public_key", &self.public_key).field("delegation_key", &self.delegation_key).field("policy_serialized", &self.policy_serialized).finish()}
  }
  #[derive(Clone)]
  pub struct EncryptedHeader {
    pub symmetric_key: Vec<u8>,
    pub encrypted_header_bytes: Vec<u8>,
  }
  impl std::fmt::Debug for EncryptedHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
      f.debug_struct("EncryptedHeader").field("symmetric_key", &self.symmetric_key).field("encrypted_header_bytes", &self.encrypted_header_bytes).finish()}
  }
  #[derive(Clone)]
  pub struct PolicyAxis {
    pub name: String,
    pub attributes: Vec<String>,
    pub hierarchical: bool,
  }
  impl std::fmt::Debug for PolicyAxis {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
      f.debug_struct("PolicyAxis").field("name", &self.name).field("attributes", &self.attributes).field("hierarchical", &self.hierarchical).finish()}
  }
  /// This struct only provides a visual way to display policy arguments
  #[derive(Clone)]
  pub struct Policy {
    pub primary_axis: PolicyAxis,
    pub secondary_axis: PolicyAxis,
  }
  impl std::fmt::Debug for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
      f.debug_struct("Policy").field("primary_axis", &self.primary_axis).field("secondary_axis", &self.secondary_axis).finish()}
  }
  #[export_name = "destroy_encryption_cache"]
  unsafe extern "C" fn __wit_bindgen_destroy_encryption_cache(arg0: i32, ) -> i32{
    let result0 = <super::Abe as Abe>::destroy_encryption_cache(arg0);
    let (result3_0,result3_1,result3_2,) = match result0{
      Ok(e) => { {
        let () = e;
        
        (0i32, 0i32, 0i32)
      }}
      Err(e) => { {
        let vec2 = (e.into_bytes()).into_boxed_slice();
        let ptr2 = vec2.as_ptr() as i32;
        let len2 = vec2.len() as i32;
        core::mem::forget(vec2);
        
        (1i32, ptr2, len2)
      }}
    };
    let ptr4 = RET_AREA.as_mut_ptr() as i32;
    *((ptr4 + 16) as *mut i32) = result3_2;
    *((ptr4 + 8) as *mut i32) = result3_1;
    *((ptr4 + 0) as *mut i32) = result3_0;
    ptr4
  }
  #[export_name = "destroy_decryption_cache"]
  unsafe extern "C" fn __wit_bindgen_destroy_decryption_cache(arg0: i32, ) -> i32{
    let result0 = <super::Abe as Abe>::destroy_decryption_cache(arg0);
    let (result3_0,result3_1,result3_2,) = match result0{
      Ok(e) => { {
        let () = e;
        
        (0i32, 0i32, 0i32)
      }}
      Err(e) => { {
        let vec2 = (e.into_bytes()).into_boxed_slice();
        let ptr2 = vec2.as_ptr() as i32;
        let len2 = vec2.len() as i32;
        core::mem::forget(vec2);
        
        (1i32, ptr2, len2)
      }}
    };
    let ptr4 = RET_AREA.as_mut_ptr() as i32;
    *((ptr4 + 16) as *mut i32) = result3_2;
    *((ptr4 + 8) as *mut i32) = result3_1;
    *((ptr4 + 0) as *mut i32) = result3_0;
    ptr4
  }
  #[export_name = "generate_user_decryption_key"]
  unsafe extern "C" fn __wit_bindgen_generate_user_decryption_key(arg0: i32, arg1: i32, arg2: i32, arg3: i32, arg4: i32, arg5: i32, arg6: i32, ) -> i32{
    let len0 = arg1 as usize;
    let len2 = arg6 as usize;
    let result3 = <super::Abe as Abe>::generate_user_decryption_key(Vec::from_raw_parts(arg0 as *mut _, len0, len0), match arg2 {
      0 => None,
      1 => Some({
        let len1 = arg4 as usize;
        
        String::from_utf8(Vec::from_raw_parts(arg3 as *mut _, len1, len1)).unwrap()
      }),
      _ => panic!("invalid enum discriminant"),
    }, Vec::from_raw_parts(arg5 as *mut _, len2, len2));
    let (result6_0,result6_1,result6_2,) = match result3{
      Ok(e) => { {
        let vec4 = (e.into_bytes()).into_boxed_slice();
        let ptr4 = vec4.as_ptr() as i32;
        let len4 = vec4.len() as i32;
        core::mem::forget(vec4);
        
        (0i32, ptr4, len4)
      }}
      Err(e) => { {
        let vec5 = (e.into_bytes()).into_boxed_slice();
        let ptr5 = vec5.as_ptr() as i32;
        let len5 = vec5.len() as i32;
        core::mem::forget(vec5);
        
        (1i32, ptr5, len5)
      }}
    };
    let ptr7 = RET_AREA.as_mut_ptr() as i32;
    *((ptr7 + 16) as *mut i32) = result6_2;
    *((ptr7 + 8) as *mut i32) = result6_1;
    *((ptr7 + 0) as *mut i32) = result6_0;
    ptr7
  }
  #[export_name = "delegate_user_decryption_key"]
  unsafe extern "C" fn __wit_bindgen_delegate_user_decryption_key(arg0: i32, arg1: i32, arg2: i32, arg3: i32, arg4: i32, arg5: i32, arg6: i32, arg7: i32, arg8: i32, ) -> i32{
    let len0 = arg1 as usize;
    let len1 = arg3 as usize;
    let len2 = arg5 as usize;
    let result4 = <super::Abe as Abe>::delegate_user_decryption_key(Vec::from_raw_parts(arg0 as *mut _, len0, len0), String::from_utf8(Vec::from_raw_parts(arg2 as *mut _, len1, len1)).unwrap(), Vec::from_raw_parts(arg4 as *mut _, len2, len2), match arg6 {
      0 => None,
      1 => Some({
        let len3 = arg8 as usize;
        
        String::from_utf8(Vec::from_raw_parts(arg7 as *mut _, len3, len3)).unwrap()
      }),
      _ => panic!("invalid enum discriminant"),
    });
    let (result7_0,result7_1,result7_2,) = match result4{
      Ok(e) => { {
        let vec5 = (e.into_bytes()).into_boxed_slice();
        let ptr5 = vec5.as_ptr() as i32;
        let len5 = vec5.len() as i32;
        core::mem::forget(vec5);
        
        (0i32, ptr5, len5)
      }}
      Err(e) => { {
        let vec6 = (e.into_bytes()).into_boxed_slice();
        let ptr6 = vec6.as_ptr() as i32;
        let len6 = vec6.len() as i32;
        core::mem::forget(vec6);
        
        (1i32, ptr6, len6)
      }}
    };
    let ptr8 = RET_AREA.as_mut_ptr() as i32;
    *((ptr8 + 16) as *mut i32) = result7_2;
    *((ptr8 + 8) as *mut i32) = result7_1;
    *((ptr8 + 0) as *mut i32) = result7_0;
    ptr8
  }
  #[export_name = "generate_master_key"]
  unsafe extern "C" fn __wit_bindgen_generate_master_key(arg0: i64, arg1: i32, arg2: i32, arg3: i32, arg4: i32, arg5: i32, arg6: i32, arg7: i32, arg8: i32, arg9: i32, arg10: i32, ) -> i32{
    let len0 = arg2 as usize;
    let base2 = arg3;
    let len2 = arg4;
    let mut result2 = Vec::with_capacity(len2 as usize);
    for i in 0..len2 {
      let base = base2 + i *8;
      result2.push({
        let len1 = *((base + 4) as *const i32) as usize;
        
        String::from_utf8(Vec::from_raw_parts(*((base + 0) as *const i32) as *mut _, len1, len1)).unwrap()
      });
    }
    std::alloc::dealloc(
    base2 as *mut _,
    std::alloc::Layout::from_size_align_unchecked(
    (len2 as usize) * 8,
    4,
    ),
    );
    let len3 = arg7 as usize;
    let base5 = arg8;
    let len5 = arg9;
    let mut result5 = Vec::with_capacity(len5 as usize);
    for i in 0..len5 {
      let base = base5 + i *8;
      result5.push({
        let len4 = *((base + 4) as *const i32) as usize;
        
        String::from_utf8(Vec::from_raw_parts(*((base + 0) as *const i32) as *mut _, len4, len4)).unwrap()
      });
    }
    std::alloc::dealloc(
    base5 as *mut _,
    std::alloc::Layout::from_size_align_unchecked(
    (len5 as usize) * 8,
    4,
    ),
    );
    let result6 = <super::Abe as Abe>::generate_master_key(arg0 as u64, Policy{primary_axis:PolicyAxis{name:String::from_utf8(Vec::from_raw_parts(arg1 as *mut _, len0, len0)).unwrap(), attributes:result2, hierarchical:match arg5 {
      0 => false,
      1 => true,
      _ => panic!("invalid enum discriminant"),
    }, }, secondary_axis:PolicyAxis{name:String::from_utf8(Vec::from_raw_parts(arg6 as *mut _, len3, len3)).unwrap(), attributes:result5, hierarchical:match arg10 {
      0 => false,
      1 => true,
      _ => panic!("invalid enum discriminant"),
    }, }, });
    let (result13_0,result13_1,result13_2,result13_3,result13_4,result13_5,result13_6,result13_7,result13_8,) = match result6{
      Ok(e) => { {
        let MasterKey{ private_key:private_key7, public_key:public_key7, delegation_key:delegation_key7, policy_serialized:policy_serialized7, } = e;
        let vec8 = (private_key7).into_boxed_slice();
        let ptr8 = vec8.as_ptr() as i32;
        let len8 = vec8.len() as i32;
        core::mem::forget(vec8);
        let vec9 = (public_key7).into_boxed_slice();
        let ptr9 = vec9.as_ptr() as i32;
        let len9 = vec9.len() as i32;
        core::mem::forget(vec9);
        let vec10 = (delegation_key7).into_boxed_slice();
        let ptr10 = vec10.as_ptr() as i32;
        let len10 = vec10.len() as i32;
        core::mem::forget(vec10);
        let vec11 = (policy_serialized7).into_boxed_slice();
        let ptr11 = vec11.as_ptr() as i32;
        let len11 = vec11.len() as i32;
        core::mem::forget(vec11);
        
        (0i32, ptr8, len8, ptr9, len9, ptr10, len10, ptr11, len11)
      }}
      Err(e) => { {
        let vec12 = (e.into_bytes()).into_boxed_slice();
        let ptr12 = vec12.as_ptr() as i32;
        let len12 = vec12.len() as i32;
        core::mem::forget(vec12);
        
        (1i32, ptr12, len12, 0i32, 0i32, 0i32, 0i32, 0i32, 0i32)
      }}
    };
    let ptr14 = RET_AREA.as_mut_ptr() as i32;
    *((ptr14 + 64) as *mut i32) = result13_8;
    *((ptr14 + 56) as *mut i32) = result13_7;
    *((ptr14 + 48) as *mut i32) = result13_6;
    *((ptr14 + 40) as *mut i32) = result13_5;
    *((ptr14 + 32) as *mut i32) = result13_4;
    *((ptr14 + 24) as *mut i32) = result13_3;
    *((ptr14 + 16) as *mut i32) = result13_2;
    *((ptr14 + 8) as *mut i32) = result13_1;
    *((ptr14 + 0) as *mut i32) = result13_0;
    ptr14
  }
  #[export_name = "decrypt"]
  unsafe extern "C" fn __wit_bindgen_decrypt(arg0: i32, arg1: i32, arg2: i32, arg3: i32, ) -> i32{
    let len0 = arg1 as usize;
    let len1 = arg3 as usize;
    let result2 = <super::Abe as Abe>::decrypt(String::from_utf8(Vec::from_raw_parts(arg0 as *mut _, len0, len0)).unwrap(), Vec::from_raw_parts(arg2 as *mut _, len1, len1));
    let (result5_0,result5_1,result5_2,) = match result2{
      Ok(e) => { {
        let vec3 = (e.into_bytes()).into_boxed_slice();
        let ptr3 = vec3.as_ptr() as i32;
        let len3 = vec3.len() as i32;
        core::mem::forget(vec3);
        
        (0i32, ptr3, len3)
      }}
      Err(e) => { {
        let vec4 = (e.into_bytes()).into_boxed_slice();
        let ptr4 = vec4.as_ptr() as i32;
        let len4 = vec4.len() as i32;
        core::mem::forget(vec4);
        
        (1i32, ptr4, len4)
      }}
    };
    let ptr6 = RET_AREA.as_mut_ptr() as i32;
    *((ptr6 + 16) as *mut i32) = result5_2;
    *((ptr6 + 8) as *mut i32) = result5_1;
    *((ptr6 + 0) as *mut i32) = result5_0;
    ptr6
  }
  #[export_name = "encrypt"]
  unsafe extern "C" fn __wit_bindgen_encrypt(arg0: i32, arg1: i32, arg2: i32, arg3: i32, arg4: i32, arg5: i32, arg6: i32, arg7: i32, arg8: i32, arg9: i32, ) -> i32{
    let len0 = arg1 as usize;
    let len1 = arg3 as usize;
    let base4 = arg4;
    let len4 = arg5;
    let mut result4 = Vec::with_capacity(len4 as usize);
    for i in 0..len4 {
      let base = base4 + i *16;
      result4.push({
        let len2 = *((base + 4) as *const i32) as usize;
        let len3 = *((base + 12) as *const i32) as usize;
        
        Attribute{axis_name:String::from_utf8(Vec::from_raw_parts(*((base + 0) as *const i32) as *mut _, len2, len2)).unwrap(), attribute:String::from_utf8(Vec::from_raw_parts(*((base + 8) as *const i32) as *mut _, len3, len3)).unwrap(), }
      });
    }
    std::alloc::dealloc(
    base4 as *mut _,
    std::alloc::Layout::from_size_align_unchecked(
    (len4 as usize) * 16,
    4,
    ),
    );
    let len5 = arg7 as usize;
    let len6 = arg9 as usize;
    let result7 = <super::Abe as Abe>::encrypt(String::from_utf8(Vec::from_raw_parts(arg0 as *mut _, len0, len0)).unwrap(), Vec::from_raw_parts(arg2 as *mut _, len1, len1), result4, Vec::from_raw_parts(arg6 as *mut _, len5, len5), Vec::from_raw_parts(arg8 as *mut _, len6, len6));
    let (result10_0,result10_1,result10_2,) = match result7{
      Ok(e) => { {
        let vec8 = (e).into_boxed_slice();
        let ptr8 = vec8.as_ptr() as i32;
        let len8 = vec8.len() as i32;
        core::mem::forget(vec8);
        
        (0i32, ptr8, len8)
      }}
      Err(e) => { {
        let vec9 = (e.into_bytes()).into_boxed_slice();
        let ptr9 = vec9.as_ptr() as i32;
        let len9 = vec9.len() as i32;
        core::mem::forget(vec9);
        
        (1i32, ptr9, len9)
      }}
    };
    let ptr11 = RET_AREA.as_mut_ptr() as i32;
    *((ptr11 + 16) as *mut i32) = result10_2;
    *((ptr11 + 8) as *mut i32) = result10_1;
    *((ptr11 + 0) as *mut i32) = result10_0;
    ptr11
  }
  #[export_name = "encrypt_hybrid_block"]
  unsafe extern "C" fn __wit_bindgen_encrypt_hybrid_block(arg0: i32, arg1: i32, arg2: i32, arg3: i32, arg4: i32, arg5: i32, arg6: i64, ) -> i32{
    let len0 = arg1 as usize;
    let len1 = arg3 as usize;
    let len2 = arg5 as usize;
    let result3 = <super::Abe as Abe>::encrypt_hybrid_block(String::from_utf8(Vec::from_raw_parts(arg0 as *mut _, len0, len0)).unwrap(), Vec::from_raw_parts(arg2 as *mut _, len1, len1), Vec::from_raw_parts(arg4 as *mut _, len2, len2), arg6 as u64);
    let (result6_0,result6_1,result6_2,) = match result3{
      Ok(e) => { {
        let vec4 = (e).into_boxed_slice();
        let ptr4 = vec4.as_ptr() as i32;
        let len4 = vec4.len() as i32;
        core::mem::forget(vec4);
        
        (0i32, ptr4, len4)
      }}
      Err(e) => { {
        let vec5 = (e.into_bytes()).into_boxed_slice();
        let ptr5 = vec5.as_ptr() as i32;
        let len5 = vec5.len() as i32;
        core::mem::forget(vec5);
        
        (1i32, ptr5, len5)
      }}
    };
    let ptr7 = RET_AREA.as_mut_ptr() as i32;
    *((ptr7 + 16) as *mut i32) = result6_2;
    *((ptr7 + 8) as *mut i32) = result6_1;
    *((ptr7 + 0) as *mut i32) = result6_0;
    ptr7
  }
  #[export_name = "rotate_attributes"]
  unsafe extern "C" fn __wit_bindgen_rotate_attributes(arg0: i32, arg1: i32, arg2: i32, arg3: i32, ) -> i32{
    let len0 = arg1 as usize;
    let base3 = arg2;
    let len3 = arg3;
    let mut result3 = Vec::with_capacity(len3 as usize);
    for i in 0..len3 {
      let base = base3 + i *16;
      result3.push({
        let len1 = *((base + 4) as *const i32) as usize;
        let len2 = *((base + 12) as *const i32) as usize;
        
        Attribute{axis_name:String::from_utf8(Vec::from_raw_parts(*((base + 0) as *const i32) as *mut _, len1, len1)).unwrap(), attribute:String::from_utf8(Vec::from_raw_parts(*((base + 8) as *const i32) as *mut _, len2, len2)).unwrap(), }
      });
    }
    std::alloc::dealloc(
    base3 as *mut _,
    std::alloc::Layout::from_size_align_unchecked(
    (len3 as usize) * 16,
    4,
    ),
    );
    let result4 = <super::Abe as Abe>::rotate_attributes(Vec::from_raw_parts(arg0 as *mut _, len0, len0), result3);
    let (result7_0,result7_1,result7_2,) = match result4{
      Ok(e) => { {
        let vec5 = (e).into_boxed_slice();
        let ptr5 = vec5.as_ptr() as i32;
        let len5 = vec5.len() as i32;
        core::mem::forget(vec5);
        
        (0i32, ptr5, len5)
      }}
      Err(e) => { {
        let vec6 = (e.into_bytes()).into_boxed_slice();
        let ptr6 = vec6.as_ptr() as i32;
        let len6 = vec6.len() as i32;
        core::mem::forget(vec6);
        
        (1i32, ptr6, len6)
      }}
    };
    let ptr8 = RET_AREA.as_mut_ptr() as i32;
    *((ptr8 + 16) as *mut i32) = result7_2;
    *((ptr8 + 8) as *mut i32) = result7_1;
    *((ptr8 + 0) as *mut i32) = result7_0;
    ptr8
  }
  #[export_name = "decrypt_hybrid_block"]
  unsafe extern "C" fn __wit_bindgen_decrypt_hybrid_block(arg0: i32, arg1: i32, arg2: i32, arg3: i32, arg4: i32, arg5: i32, arg6: i64, ) -> i32{
    let len0 = arg1 as usize;
    let len1 = arg3 as usize;
    let len2 = arg5 as usize;
    let result3 = <super::Abe as Abe>::decrypt_hybrid_block(Vec::from_raw_parts(arg0 as *mut _, len0, len0), Vec::from_raw_parts(arg2 as *mut _, len1, len1), Vec::from_raw_parts(arg4 as *mut _, len2, len2), arg6 as u64);
    let (result6_0,result6_1,result6_2,) = match result3{
      Ok(e) => { {
        let vec4 = (e).into_boxed_slice();
        let ptr4 = vec4.as_ptr() as i32;
        let len4 = vec4.len() as i32;
        core::mem::forget(vec4);
        
        (0i32, ptr4, len4)
      }}
      Err(e) => { {
        let vec5 = (e.into_bytes()).into_boxed_slice();
        let ptr5 = vec5.as_ptr() as i32;
        let len5 = vec5.len() as i32;
        core::mem::forget(vec5);
        
        (1i32, ptr5, len5)
      }}
    };
    let ptr7 = RET_AREA.as_mut_ptr() as i32;
    *((ptr7 + 16) as *mut i32) = result6_2;
    *((ptr7 + 8) as *mut i32) = result6_1;
    *((ptr7 + 0) as *mut i32) = result6_0;
    ptr7
  }
  #[export_name = "create_decryption_cache"]
  unsafe extern "C" fn __wit_bindgen_create_decryption_cache(arg0: i32, arg1: i32, ) -> i32{
    let len0 = arg1 as usize;
    let result1 = <super::Abe as Abe>::create_decryption_cache(Vec::from_raw_parts(arg0 as *mut _, len0, len0));
    let (result3_0,result3_1,result3_2,) = match result1{
      Ok(e) => { (0i32, wit_bindgen_rust::rt::as_i32(e), 0i32)}
      Err(e) => { {
        let vec2 = (e.into_bytes()).into_boxed_slice();
        let ptr2 = vec2.as_ptr() as i32;
        let len2 = vec2.len() as i32;
        core::mem::forget(vec2);
        
        (1i32, ptr2, len2)
      }}
    };
    let ptr4 = RET_AREA.as_mut_ptr() as i32;
    *((ptr4 + 16) as *mut i32) = result3_2;
    *((ptr4 + 8) as *mut i32) = result3_1;
    *((ptr4 + 0) as *mut i32) = result3_0;
    ptr4
  }
  #[export_name = "create_encryption_cache"]
  unsafe extern "C" fn __wit_bindgen_create_encryption_cache(arg0: i32, arg1: i32, arg2: i32, arg3: i32, ) -> i32{
    let len0 = arg1 as usize;
    let len1 = arg3 as usize;
    let result2 = <super::Abe as Abe>::create_encryption_cache(Vec::from_raw_parts(arg0 as *mut _, len0, len0), Vec::from_raw_parts(arg2 as *mut _, len1, len1));
    let (result4_0,result4_1,result4_2,) = match result2{
      Ok(e) => { (0i32, wit_bindgen_rust::rt::as_i32(e), 0i32)}
      Err(e) => { {
        let vec3 = (e.into_bytes()).into_boxed_slice();
        let ptr3 = vec3.as_ptr() as i32;
        let len3 = vec3.len() as i32;
        core::mem::forget(vec3);
        
        (1i32, ptr3, len3)
      }}
    };
    let ptr5 = RET_AREA.as_mut_ptr() as i32;
    *((ptr5 + 16) as *mut i32) = result4_2;
    *((ptr5 + 8) as *mut i32) = result4_1;
    *((ptr5 + 0) as *mut i32) = result4_0;
    ptr5
  }
  #[export_name = "encrypt_hybrid_header"]
  unsafe extern "C" fn __wit_bindgen_encrypt_hybrid_header(arg0: i32, arg1: i32, arg2: i32, arg3: i32, arg4: i32, ) -> i32{
    let base2 = arg0;
    let len2 = arg1;
    let mut result2 = Vec::with_capacity(len2 as usize);
    for i in 0..len2 {
      let base = base2 + i *16;
      result2.push({
        let len0 = *((base + 4) as *const i32) as usize;
        let len1 = *((base + 12) as *const i32) as usize;
        
        Attribute{axis_name:String::from_utf8(Vec::from_raw_parts(*((base + 0) as *const i32) as *mut _, len0, len0)).unwrap(), attribute:String::from_utf8(Vec::from_raw_parts(*((base + 8) as *const i32) as *mut _, len1, len1)).unwrap(), }
      });
    }
    std::alloc::dealloc(
    base2 as *mut _,
    std::alloc::Layout::from_size_align_unchecked(
    (len2 as usize) * 16,
    4,
    ),
    );
    let len3 = arg4 as usize;
    let result4 = <super::Abe as Abe>::encrypt_hybrid_header(result2, arg2, Vec::from_raw_parts(arg3 as *mut _, len3, len3));
    let (result9_0,result9_1,result9_2,result9_3,result9_4,) = match result4{
      Ok(e) => { {
        let EncryptedHeader{ symmetric_key:symmetric_key5, encrypted_header_bytes:encrypted_header_bytes5, } = e;
        let vec6 = (symmetric_key5).into_boxed_slice();
        let ptr6 = vec6.as_ptr() as i32;
        let len6 = vec6.len() as i32;
        core::mem::forget(vec6);
        let vec7 = (encrypted_header_bytes5).into_boxed_slice();
        let ptr7 = vec7.as_ptr() as i32;
        let len7 = vec7.len() as i32;
        core::mem::forget(vec7);
        
        (0i32, ptr6, len6, ptr7, len7)
      }}
      Err(e) => { {
        let vec8 = (e.into_bytes()).into_boxed_slice();
        let ptr8 = vec8.as_ptr() as i32;
        let len8 = vec8.len() as i32;
        core::mem::forget(vec8);
        
        (1i32, ptr8, len8, 0i32, 0i32)
      }}
    };
    let ptr10 = RET_AREA.as_mut_ptr() as i32;
    *((ptr10 + 32) as *mut i32) = result9_4;
    *((ptr10 + 24) as *mut i32) = result9_3;
    *((ptr10 + 16) as *mut i32) = result9_2;
    *((ptr10 + 8) as *mut i32) = result9_1;
    *((ptr10 + 0) as *mut i32) = result9_0;
    ptr10
  }
  #[export_name = "decrypt_hybrid_header"]
  unsafe extern "C" fn __wit_bindgen_decrypt_hybrid_header(arg0: i32, arg1: i32, arg2: i32, ) -> i32{
    let len0 = arg2 as usize;
    let result1 = <super::Abe as Abe>::decrypt_hybrid_header(arg0, Vec::from_raw_parts(arg1 as *mut _, len0, len0));
    let (result4_0,result4_1,result4_2,) = match result1{
      Ok(e) => { {
        let vec2 = (e.into_bytes()).into_boxed_slice();
        let ptr2 = vec2.as_ptr() as i32;
        let len2 = vec2.len() as i32;
        core::mem::forget(vec2);
        
        (0i32, ptr2, len2)
      }}
      Err(e) => { {
        let vec3 = (e.into_bytes()).into_boxed_slice();
        let ptr3 = vec3.as_ptr() as i32;
        let len3 = vec3.len() as i32;
        core::mem::forget(vec3);
        
        (1i32, ptr3, len3)
      }}
    };
    let ptr5 = RET_AREA.as_mut_ptr() as i32;
    *((ptr5 + 16) as *mut i32) = result4_2;
    *((ptr5 + 8) as *mut i32) = result4_1;
    *((ptr5 + 0) as *mut i32) = result4_0;
    ptr5
  }
  pub trait Abe {
    /// This is a generated file by witgen (https://github.com/bnjjj/witgen), please do not edit yourself, you can generate a new one thanks to cargo witgen generate command
    fn destroy_encryption_cache(cache_handle: i32,) -> Result<(),String>;
    fn destroy_decryption_cache(cache_handle: i32,) -> Result<(),String>;
    /// Generate a user decryption key for the given master key and access policy
    fn generate_user_decryption_key(master_private_key: Vec<u8>,access_policy: Option<String>,policy: Vec<u8>,) -> Result<String,String>;
    /// Generate a delegate user decryption key for the access policy
    fn delegate_user_decryption_key(delegation_key: Vec<u8>,user_decryption_key: String,policy: Vec<u8>,access_policy: Option<String>,) -> Result<String,String>;
    /// Generate ABE master key
    fn generate_master_key(nb_revocation: u64,policy: Policy,) -> Result<MasterKey,String>;
    /// Decrypt ABE-ciphertext (decrypt ABE header + decrypt AES)
    fn decrypt(user_decryption_key: String,encrypted_data: Vec<u8>,) -> Result<String,String>;
    /// Encrypt an AES-symmetric key and encrypt with AESGCM-256
    fn encrypt(plaintext: String,master_public_key: Vec<u8>,attributes: Vec<Attribute>,policy: Vec<u8>,uid: Vec<u8>,) -> Result<Vec<u8>,String>;
    /// Encrypt an AES-symmetric key and encrypt with AESGCM-256
    fn encrypt_hybrid_block(plaintext: String,symmetric_key: Vec<u8>,uid: Vec<u8>,block_number: u64,) -> Result<Vec<u8>,String>;
    /// Rotating ABE attributes
    fn rotate_attributes(policy: Vec<u8>,attributes: Vec<Attribute>,) -> Result<Vec<u8>,String>;
    /// Decrypt symmetric block cipher
    fn decrypt_hybrid_block(ciphertext: Vec<u8>,symmetric_key: Vec<u8>,uid: Vec<u8>,block_number: u64,) -> Result<Vec<u8>,String>;
    /// Prepare encryption cache (avoiding public key deserialization)
    fn create_decryption_cache(user_decryption_key: Vec<u8>,) -> Result<i32,String>;
    /// Prepare encryption cache (avoiding public key deserialization)
    fn create_encryption_cache(master_public_key: Vec<u8>,policy: Vec<u8>,) -> Result<i32,String>;
    /// Encrypt an AES-symmetric key and encrypt with AESGCM-256
    fn encrypt_hybrid_header(attributes: Vec<Attribute>,cache_handle: i32,uid: Vec<u8>,) -> Result<EncryptedHeader,String>;
    /// Decrypt ABE-ciphertext (decrypt ABE header)
    fn decrypt_hybrid_header(cache_handle: i32,encrypted_data: Vec<u8>,) -> Result<String,String>;
  }
  static mut RET_AREA: [i64; 9] = [0; 9];
}
