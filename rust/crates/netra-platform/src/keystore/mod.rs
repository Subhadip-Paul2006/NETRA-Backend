pub mod factory;
pub mod linux;
pub mod macos;
pub mod windows;

#[cfg(feature = "insecure-dev-keystore")]
pub mod dev_insecure;

#[cfg(feature = "insecure-dev-keystore")]
pub use factory::create_insecure_dev_keystore;
pub use factory::create_platform_keystore;
pub use linux::LinuxSecretServiceKeystore;
pub use macos::MacosKeychainKeystore;
pub use windows::WindowsDpapiKeystore;
