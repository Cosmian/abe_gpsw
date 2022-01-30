mod statics;
pub use statics::*;

// TODO de-activated because it creates strange SIGSEGV when used through FFI
// mod structs;

#[cfg(test)]
mod tests;
