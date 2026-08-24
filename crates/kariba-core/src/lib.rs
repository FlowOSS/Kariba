pub mod clamav;
pub mod config;
pub mod distro;
pub mod init;
pub mod paths;

pub use distro::{Distro, DistroFamily, detect_distro};
pub use init::{InitSystem, detect_init};
