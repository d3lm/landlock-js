//! Implements the Landlock bindings on top of the landlock crate. The crate
//! root compiles this module only on Linux, so nothing in here needs its own
//! target gate.

use landlock::{
  Access, AccessFs, AccessNet, BitFlags, CompatLevel, Compatible, NetPort, PathBeneath, PathFd, RestrictSelf,
  RestrictSelfAttr, Ruleset, RulesetAttr, RulesetCreated, RulesetCreatedAttr, RulesetStatus, Scope, ABI,
};
use napi::bindgen_prelude::*;
use napi_derive::napi;
use std::path::Path;

use crate::{RestrictSelfFlagsOptions, RestrictSelfFlagsStatus, RestrictSelfOptions, RestrictionStatus};

// these query flags come from include/uapi/linux/landlock.h
const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1 << 0;
const LANDLOCK_CREATE_RULESET_ERRATA: u32 = 1 << 1;

/// Queries the kernel through landlock_create_ruleset(2) with a null attribute
/// and one of the query flags above. The landlock crate caps the ABI it reports
/// at the newest version it knows, so the raw syscall is used here to surface
/// the real kernel value. A negative result means the kernel lacks Landlock or
/// predates the query flag.
fn query_landlock_create_ruleset_flag(flag: u32) -> i32 {
  use libc::{c_long, syscall, SYS_landlock_create_ruleset};

  /*
   * The call is sound because these query flags require a null attribute
   * pointer with a zero size, so the kernel never dereferences the pointer
   * and only reports an integer back.
   */
  unsafe {
    syscall(
      SYS_landlock_create_ruleset as c_long,
      std::ptr::null::<libc::c_void>(),
      0usize,
      flag,
    ) as i32
  }
}

fn parse_fs_access(access: Vec<String>) -> Result<BitFlags<AccessFs>> {
  let mut fs_access = BitFlags::<AccessFs>::empty();

  for access_str in access {
    let access_flag = match access_str.as_str() {
      "execute" => AccessFs::Execute,
      "write_file" => AccessFs::WriteFile,
      "read_file" => AccessFs::ReadFile,
      "read_dir" => AccessFs::ReadDir,
      "remove_dir" => AccessFs::RemoveDir,
      "remove_file" => AccessFs::RemoveFile,
      "make_char" => AccessFs::MakeChar,
      "make_dir" => AccessFs::MakeDir,
      "make_reg" => AccessFs::MakeReg,
      "make_sock" => AccessFs::MakeSock,
      "make_fifo" => AccessFs::MakeFifo,
      "make_block" => AccessFs::MakeBlock,
      "make_sym" => AccessFs::MakeSym,
      "refer" => AccessFs::Refer,
      "truncate" => AccessFs::Truncate,
      "ioctl_dev" => AccessFs::IoctlDev,
      "resolve_unix" => AccessFs::ResolveUnix,
      _ => return Err(Error::from_reason(format!("Unknown fs access: {}", access_str))),
    };

    fs_access |= access_flag;
  }

  Ok(fs_access)
}

fn parse_net_access(access: Vec<String>) -> Result<BitFlags<AccessNet>> {
  let mut net_access = BitFlags::<AccessNet>::empty();

  for access_str in access {
    let access_flag = match access_str.as_str() {
      "bind_tcp" => AccessNet::BindTcp,
      "connect_tcp" => AccessNet::ConnectTcp,
      _ => return Err(Error::from_reason(format!("Unknown net access: {}", access_str))),
    };

    net_access |= access_flag;
  }

  Ok(net_access)
}

fn parse_scopes(scopes: Vec<String>) -> Result<BitFlags<Scope>> {
  let mut scope_flags = BitFlags::<Scope>::empty();

  for scope in scopes {
    let flag = match scope.as_str() {
      "signal" => Scope::Signal,
      "abstract_unix_socket" => Scope::AbstractUnixSocket,
      _ => return Err(Error::from_reason(format!("Unknown scope: {}", scope))),
    };

    scope_flags |= flag;
  }

  Ok(scope_flags)
}

fn parse_compat_level(level: &str) -> Result<CompatLevel> {
  match level {
    "best_effort" => Ok(CompatLevel::BestEffort),
    "soft_requirement" => Ok(CompatLevel::SoftRequirement),
    "hard_requirement" => Ok(CompatLevel::HardRequirement),
    _ => Err(Error::from_reason(format!("Unknown compatibility level: {}", level))),
  }
}

/// Applies the restrict-self options to a created ruleset. Every flag setter
/// runs its own compatibility check, so an unsupported flag surfaces here
/// under a hard requirement instead of at enforcement time.
fn apply_restrict_options(mut created: RulesetCreated, options: RestrictSelfOptions) -> Result<RulesetCreated> {
  if let Some(set) = options.log_same_exec {
    created = created
      .log_same_exec(set)
      .map_err(|error| Error::from_reason(format!("Failed to set log_same_exec: {}", error)))?;
  }

  if let Some(set) = options.log_new_exec {
    created = created
      .log_new_exec(set)
      .map_err(|error| Error::from_reason(format!("Failed to set log_new_exec: {}", error)))?;
  }

  if let Some(set) = options.log_subdomains {
    created = created
      .log_subdomains(set)
      .map_err(|error| Error::from_reason(format!("Failed to set log_subdomains: {}", error)))?;
  }

  if let Some(set) = options.all_threads {
    created = created
      .all_threads(set)
      .map_err(|error| Error::from_reason(format!("Failed to set all_threads: {}", error)))?;
  }

  if let Some(set) = options.no_new_privs {
    created = created.no_new_privs(set);
  }

  Ok(created)
}

#[napi]
pub struct LandlockRuleset {
  inner: Option<Ruleset>,
  created: Option<RulesetCreated>,
}

impl Default for LandlockRuleset {
  fn default() -> Self {
    Self {
      inner: Some(Ruleset::default()),
      created: None,
    }
  }
}

#[napi]
impl LandlockRuleset {
  #[napi(constructor)]
  pub fn new() -> Self {
    Self::default()
  }

  #[napi]
  pub fn handle_fs_access(&mut self, access: Vec<String>) -> Result<()> {
    let ruleset = self
      .inner
      .as_mut()
      .ok_or_else(|| Error::from_reason("Ruleset already created"))?;

    let fs_access = parse_fs_access(access)?;

    ruleset
      .handle_access(fs_access)
      .map_err(|error| Error::from_reason(format!("Failed to handle fs access: {}", error)))?;

    Ok(())
  }

  #[napi]
  pub fn handle_net_access(&mut self, access: Vec<String>) -> Result<()> {
    let ruleset = self
      .inner
      .as_mut()
      .ok_or_else(|| Error::from_reason("Ruleset already created"))?;

    let net_access = parse_net_access(access)?;

    ruleset
      .handle_access(net_access)
      .map_err(|error| Error::from_reason(format!("Failed to handle net access: {}", error)))?;

    Ok(())
  }

  #[napi]
  pub fn handle_scopes(&mut self, scopes: Vec<String>) -> Result<()> {
    let ruleset = self
      .inner
      .as_mut()
      .ok_or_else(|| Error::from_reason("Ruleset already created"))?;

    let scope_flags = parse_scopes(scopes)?;

    ruleset
      .scope(scope_flags)
      .map_err(|error| Error::from_reason(format!("Failed to handle scopes: {error}")))?;

    Ok(())
  }

  #[napi]
  pub fn add_path_rule(&mut self, path: String, access: Vec<String>) -> Result<()> {
    let created = self
      .created
      .as_mut()
      .ok_or_else(|| Error::from_reason("Ruleset not created yet. Call create() first"))?;

    let fs_access = parse_fs_access(access)?;

    let path_fd = PathFd::new(Path::new(&path))
      .map_err(|error| Error::from_reason(format!("Failed to open path {}: {}", path, error)))?;

    let rule = PathBeneath::new(path_fd, fs_access);

    created
      .add_rule(rule)
      .map_err(|error| Error::from_reason(format!("Failed to add path rule: {}", error)))?;

    Ok(())
  }

  #[napi]
  pub fn add_net_port_rule(&mut self, port: u16, access: Vec<String>) -> Result<()> {
    let created = self
      .created
      .as_mut()
      .ok_or_else(|| Error::from_reason("Ruleset not created yet. Call create() first"))?;

    let net_access = parse_net_access(access)?;

    let rule = NetPort::new(port, net_access);

    created
      .add_rule(rule)
      .map_err(|error| Error::from_reason(format!("Failed to add net port rule: {}", error)))?;

    Ok(())
  }

  #[napi]
  pub fn set_compatibility(&mut self, level: String) -> Result<()> {
    let ruleset = self
      .inner
      .as_mut()
      .ok_or_else(|| Error::from_reason("Ruleset already created"))?;

    let compat_level = parse_compat_level(&level)?;

    ruleset.set_compatibility(compat_level);

    Ok(())
  }

  #[napi]
  pub fn create(&mut self) -> Result<()> {
    let ruleset = self
      .inner
      .take()
      .ok_or_else(|| Error::from_reason("Ruleset already created"))?;

    let created = ruleset
      .create()
      .map_err(|error| Error::from_reason(format!("Failed to create ruleset: {}", error)))?;

    self.created = Some(created);

    Ok(())
  }

  #[napi]
  pub fn restrict_self(&mut self, options: Option<RestrictSelfOptions>) -> Result<RestrictionStatus> {
    let mut created = self
      .created
      .take()
      .ok_or_else(|| Error::from_reason("Ruleset not created yet"))?;

    if let Some(options) = options {
      created = apply_restrict_options(created, options)?;
    }

    let status = created
      .restrict_self()
      .map_err(|error| Error::from_reason(format!("Failed to restrict self: {}", error)))?;

    let ruleset_status = match status.ruleset {
      RulesetStatus::NotEnforced => "not_enforced",
      RulesetStatus::PartiallyEnforced => "partially_enforced",
      RulesetStatus::FullyEnforced => "fully_enforced",
    };

    Ok(RestrictionStatus {
      ruleset: ruleset_status.to_string(),
      no_new_privs: status.no_new_privs,
      log_same_exec: status.log_same_exec,
      log_new_exec: status.log_new_exec,
      log_subdomains: status.log_subdomains,
      all_threads: status.all_threads,
    })
  }
}

/// Calls landlock_restrict_self(2) with a ruleset file descriptor of -1, which
/// applies restrict-self flags without creating a new Landlock domain. The kernel
/// only accepts muting subdomain logs on this path. Since Landlock ABI 9 (Linux 7.1)
/// the all-threads flag can be combined with it, while ABI 8 kernels reject that
/// combination with EBADF even though they support the flag together with a ruleset.
#[napi]
pub fn apply_restrict_self_flags(options: Option<RestrictSelfFlagsOptions>) -> Result<RestrictSelfFlagsStatus> {
  let mut builder = RestrictSelf::default();

  if let Some(options) = options {
    if let Some(level) = options.compatibility {
      builder = builder.set_compatibility(parse_compat_level(&level)?);
    }

    if let Some(set) = options.log_subdomains {
      builder = builder
        .log_subdomains(set)
        .map_err(|error| Error::from_reason(format!("Failed to set log_subdomains: {}", error)))?;
    }

    if let Some(set) = options.all_threads {
      builder = builder
        .all_threads(set)
        .map_err(|error| Error::from_reason(format!("Failed to set all_threads: {}", error)))?;
    }

    if let Some(set) = options.no_new_privs {
      builder = builder.no_new_privs(set);
    }
  }

  let status = builder
    .apply()
    .map_err(|error| Error::from_reason(format!("Failed to apply restrict-self flags: {}", error)))?;

  Ok(RestrictSelfFlagsStatus {
    no_new_privs: status.no_new_privs,
    log_subdomains: status.log_subdomains,
    all_threads: status.all_threads,
  })
}

#[napi]
pub fn get_abi_version() -> i32 {
  query_landlock_create_ruleset_flag(LANDLOCK_CREATE_RULESET_VERSION).max(0)
}

#[napi]
pub fn get_errata() -> i32 {
  query_landlock_create_ruleset_flag(LANDLOCK_CREATE_RULESET_ERRATA).max(0)
}

#[napi]
pub fn is_landlock_supported() -> bool {
  Ruleset::default()
    .set_compatibility(CompatLevel::HardRequirement)
    .handle_access(AccessFs::from_all(ABI::V1))
    .and_then(|ruleset| ruleset.create())
    .is_ok()
}
