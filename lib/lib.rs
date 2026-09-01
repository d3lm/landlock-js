//! Provides the Node.js bindings for Linux Landlock.
//!
//! The crate root holds the plain data types that cross the N-API boundary,
//! because they compile on every platform. Everything that touches the
//! landlock crate or the kernel lives in the `linux` module behind the single
//! target gate below. The TypeScript entry point never loads a native binding
//! on another platform, so a non-Linux build only needs to compile and does
//! not need to export anything.

use napi_derive::napi;

/*
 * napi-derive compiles out the ctor registration of every export under cfg(test),
 * which leaves the generated bindings in this module unreferenced in the lib test
 * target.
 */
#[cfg(target_os = "linux")]
#[cfg_attr(test, expect(dead_code))]
mod linux;

/// Result of enforcing a ruleset on the current process.
#[napi(object)]
pub struct RestrictionStatus {
  pub ruleset: String,

  #[napi(js_name = "no_new_privs")]
  pub no_new_privs: bool,

  #[napi(js_name = "log_same_exec")]
  pub log_same_exec: bool,

  #[napi(js_name = "log_new_exec")]
  pub log_new_exec: bool,

  #[napi(js_name = "log_subdomains")]
  pub log_subdomains: bool,

  #[napi(js_name = "all_threads")]
  pub all_threads: bool,
}

/// Options for enforcing a ruleset on the current process.
#[napi(object)]
pub struct RestrictSelfOptions {
  #[napi(js_name = "log_same_exec")]
  pub log_same_exec: Option<bool>,

  #[napi(js_name = "log_new_exec")]
  pub log_new_exec: Option<bool>,

  #[napi(js_name = "log_subdomains")]
  pub log_subdomains: Option<bool>,

  #[napi(js_name = "all_threads")]
  pub all_threads: Option<bool>,

  #[napi(js_name = "no_new_privs")]
  pub no_new_privs: Option<bool>,
}

/// Options for applying restrict-self flags without a ruleset.
#[napi(object)]
pub struct RestrictSelfFlagsOptions {
  #[napi(js_name = "log_subdomains")]
  pub log_subdomains: Option<bool>,

  #[napi(js_name = "all_threads")]
  pub all_threads: Option<bool>,

  #[napi(js_name = "no_new_privs")]
  pub no_new_privs: Option<bool>,

  pub compatibility: Option<String>,
}

/// Result of applying restrict-self flags without a ruleset.
#[napi(object)]
pub struct RestrictSelfFlagsStatus {
  #[napi(js_name = "no_new_privs")]
  pub no_new_privs: bool,

  #[napi(js_name = "log_subdomains")]
  pub log_subdomains: bool,

  #[napi(js_name = "all_threads")]
  pub all_threads: bool,
}
