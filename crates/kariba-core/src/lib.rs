pub mod distro;
pub mod init;

pub use distro::{Distro, DistroFamily, detect_distro};
pub use init::{InitSystem, detect_init};
