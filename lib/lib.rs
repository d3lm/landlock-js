use napi::bindgen_prelude::*;
use napi_derive::napi;

#[cfg(target_os = "linux")]
use landlock::{
  Access, AccessFs, AccessNet, BitFlags, CompatLevel, Compatible, PathBeneath, PathFd, RestrictSelf, RestrictSelfAttr,
  Ruleset, RulesetAttr, RulesetCreated, RulesetCreatedAttr, RulesetStatus, Scope, ABI,
};

#[cfg(target_os = "linux")]
use std::path::Path;

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

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
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
#[cfg(target_os = "linux")]
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
  #[cfg(target_os = "linux")]
  inner: Option<Ruleset>,

  #[cfg(target_os = "linux")]
  created: Option<RulesetCreated>,
}

#[napi]
impl LandlockRuleset {
  #[napi(constructor)]
  pub fn new() -> Result<Self> {
    #[cfg(target_os = "linux")]
    {
      Ok(Self {
        inner: Some(Ruleset::default()),
        created: None,
      })
    }

    #[cfg(not(target_os = "linux"))]
    {
      Err(Error::from_reason("Landlock is only supported on Linux"))
    }
  }

  #[napi]
  pub fn handle_fs_access(&mut self, access: Vec<String>) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
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

    #[cfg(not(target_os = "linux"))]
    {
      let _ = access;

      Err(Error::from_reason("Landlock is only supported on Linux"))
    }
  }

  #[napi]
  pub fn handle_net_access(&mut self, access: Vec<String>) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
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

    #[cfg(not(target_os = "linux"))]
    {
      let _ = access;

      Err(Error::from_reason("Landlock is only supported on Linux"))
    }
  }

  #[napi]
  pub fn handle_scopes(&mut self, scopes: Vec<String>) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
      let ruleset = self
        .inner
        .as_mut()
        .ok_or_else(|| Error::from_reason("Ruleset already created"))?;

      let mut scope_flags = BitFlags::<Scope>::empty();

      for scope in scopes {
        let flag = match scope.as_str() {
          "signal" => Scope::Signal,
          "abstract_unix_socket" => Scope::AbstractUnixSocket,
          _ => return Err(Error::from_reason(format!("Unknown scope: {}", scope))),
        };

        scope_flags |= flag;
      }

      ruleset
        .scope(scope_flags)
        .map_err(|error| Error::from_reason(format!("Failed to handle scopes: {error}")))?;

      Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    {
      let _ = scopes;

      Err(Error::from_reason("Landlock is only supported on Linux"))
    }
  }

  #[napi]
  pub fn add_path_rule(&mut self, path: String, access: Vec<String>) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
      let created = self
        .created
        .as_mut()
        .ok_or_else(|| Error::from_reason("Ruleset not created yet. Call create() first"))?;

      let fs_access = parse_fs_access(access)?;

      let path_fd = PathFd::new(&Path::new(&path))
        .map_err(|error| Error::from_reason(format!("Failed to open path {}: {}", path, error)))?;

      let rule = PathBeneath::new(path_fd, fs_access);

      created
        .add_rule(rule)
        .map_err(|error| Error::from_reason(format!("Failed to add path rule: {}", error)))?;

      Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    {
      let _ = (path, access);

      Err(Error::from_reason("Landlock is only supported on Linux"))
    }
  }

  #[napi]
  pub fn add_net_port_rule(&mut self, port: u16, access: Vec<String>) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
      let created = self
        .created
        .as_mut()
        .ok_or_else(|| Error::from_reason("Ruleset not created yet. Call create() first"))?;

      let net_access = parse_net_access(access)?;

      let rule = landlock::NetPort::new(port, net_access);

      created
        .add_rule(rule)
        .map_err(|error| Error::from_reason(format!("Failed to add net port rule: {}", error)))?;

      Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
      let _ = (port, access);

      Err(Error::from_reason("Landlock is only supported on Linux"))
    }
  }

  #[napi]
  pub fn set_compatibility(&mut self, level: String) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
      let ruleset = self
        .inner
        .as_mut()
        .ok_or_else(|| Error::from_reason("Ruleset already created"))?;

      let compat_level = parse_compat_level(&level)?;

      ruleset.set_compatibility(compat_level);

      Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    {
      let _ = level;

      Err(Error::from_reason("Landlock is only supported on Linux"))
    }
  }

  #[napi]
  pub fn create(&mut self) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
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

    #[cfg(not(target_os = "linux"))]
    {
      Err(Error::from_reason("Landlock is only supported on Linux"))
    }
  }

  #[napi]
  pub fn restrict_self(&mut self, options: Option<RestrictSelfOptions>) -> Result<RestrictionStatus> {
    #[cfg(target_os = "linux")]
    {
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

    #[cfg(not(target_os = "linux"))]
    {
      let _ = options;

      Ok(RestrictionStatus {
        ruleset: "not_enforced".to_string(),
        no_new_privs: false,
        log_same_exec: true,
        log_new_exec: false,
        log_subdomains: true,
        all_threads: false,
      })
    }
  }
}

/// Calls landlock_restrict_self(2) with a ruleset file descriptor of -1, which
/// applies restrict-self flags without creating a new Landlock domain. The
/// kernel only accepts muting subdomain logs on this path, optionally combined
/// with the all-threads flag.
#[napi]
pub fn apply_restrict_self_flags(options: Option<RestrictSelfFlagsOptions>) -> Result<RestrictSelfFlagsStatus> {
  #[cfg(target_os = "linux")]
  {
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

  #[cfg(not(target_os = "linux"))]
  {
    let _ = options;

    Err(Error::from_reason("Landlock is only supported on Linux"))
  }
}

#[napi]
pub fn get_abi_version() -> i32 {
  #[cfg(target_os = "linux")]
  {
    let abi = query_landlock_create_ruleset_flag(LANDLOCK_CREATE_RULESET_VERSION);

    if abi > 0 {
      abi
    } else {
      0
    }
  }

  #[cfg(not(target_os = "linux"))]
  {
    0
  }
}

#[napi]
pub fn get_errata() -> i32 {
  #[cfg(target_os = "linux")]
  {
    let errata = query_landlock_create_ruleset_flag(LANDLOCK_CREATE_RULESET_ERRATA);

    if errata > 0 {
      errata
    } else {
      0
    }
  }

  #[cfg(not(target_os = "linux"))]
  {
    0
  }
}

#[napi]
pub fn is_landlock_supported() -> bool {
  #[cfg(target_os = "linux")]
  {
    match Ruleset::default()
      .set_compatibility(CompatLevel::HardRequirement)
      .handle_access(AccessFs::from_all(ABI::V1))
    {
      Ok(ruleset) => match ruleset.create() {
        Ok(_) => true,
        Err(_) => false,
      },
      Err(_) => false,
    }
  }

  #[cfg(not(target_os = "linux"))]
  {
    false
  }
}

// from include/uapi/linux/landlock.h
#[cfg(target_os = "linux")]
const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1 << 0;

#[cfg(target_os = "linux")]
const LANDLOCK_CREATE_RULESET_ERRATA: u32 = 1 << 1;

#[cfg(target_os = "linux")]
fn query_landlock_create_ruleset_flag(flag: u32) -> i32 {
  use libc::{c_long, syscall, SYS_landlock_create_ruleset};

  unsafe {
    syscall(
      SYS_landlock_create_ruleset as c_long,
      std::ptr::null::<libc::c_void>(),
      0usize,
      flag,
    ) as i32
  }
}
