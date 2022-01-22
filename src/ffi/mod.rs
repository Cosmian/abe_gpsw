pub mod error;

#[no_mangle]
pub extern "C" fn square(x: i32) -> i32 {
    x * x
}
