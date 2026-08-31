use napi::bindgen_prelude::*;
use napi_derive::napi;

#[cfg(target_os = "linux")]
use landlock::{
  Access, AccessFs, AccessNet, BitFlags, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset, RulesetAttr,
  RulesetCreated, RulesetCreatedAttr, RulesetStatus, Scope, ABI,
};

#[cfg(target_os = "linux")]
use std::path::Path;

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
          _ => return Err(Error::from_reason(format!("Unknown fs access: {}", access_str))),
        };

        fs_access |= access_flag;
      }

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

      let mut net_access = BitFlags::<AccessNet>::empty();

      for access_str in access {
        let access_flag = match access_str.as_str() {
          "bind_tcp" => AccessNet::BindTcp,
          "connect_tcp" => AccessNet::ConnectTcp,
          _ => return Err(Error::from_reason(format!("Unknown net access: {}", access_str))),
        };

        net_access |= access_flag;
      }

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
          _ => return Err(Error::from_reason(format!("Unknown fs access: {}", access_str))),
        };

        fs_access |= access_flag;
      }

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

      let mut net_access = BitFlags::<AccessNet>::empty();

      for access_str in access {
        let access_flag = match access_str.as_str() {
          "bind_tcp" => AccessNet::BindTcp,
          "connect_tcp" => AccessNet::ConnectTcp,
          _ => return Err(Error::from_reason(format!("Unknown net access: {}", access_str))),
        };

        net_access |= access_flag;
      }

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

      let compat_level = match level.as_str() {
        "best_effort" => CompatLevel::BestEffort,
        "soft_requirement" => CompatLevel::SoftRequirement,
        "hard_requirement" => CompatLevel::HardRequirement,
        _ => return Err(Error::from_reason(format!("Unknown compatibility level: {}", level))),
      };

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
  pub fn restrict_self(&mut self, env: &Env) -> Result<Object<'_>> {
    #[cfg(target_os = "linux")]
    {
      let created = self
        .created
        .take()
        .ok_or_else(|| Error::from_reason("Ruleset not created yet"))?;

      let status = created
        .restrict_self()
        .map_err(|error| Error::from_reason(format!("Failed to restrict self: {}", error)))?;

      let mut result = Object::new(env)?;

      let ruleset_status = match status.ruleset {
        RulesetStatus::NotEnforced => "not_enforced",
        RulesetStatus::PartiallyEnforced => "partially_enforced",
        RulesetStatus::FullyEnforced => "fully_enforced",
      };

      result.set("ruleset", ruleset_status)?;
      result.set("no_new_privs", status.no_new_privs)?;

      Ok(result)
    }

    #[cfg(not(target_os = "linux"))]
    {
      let mut result = Object::new(env)?;

      result.set("ruleset", "not_enforced")?;
      result.set("no_new_privs", false)?;

      Ok(result)
    }
  }
}

#[napi]
pub fn get_abi_version() -> i32 {
  #[cfg(target_os = "linux")]
  {
    let abi = query_landlock_abi_raw();

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

#[cfg(target_os = "linux")]
fn query_landlock_abi_raw() -> i32 {
  use libc::{c_long, syscall, SYS_landlock_create_ruleset};

  // from include/uapi/linux/landlock.h
  const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1 << 0;

  unsafe {
    let abi_version = syscall(
      SYS_landlock_create_ruleset as c_long,
      std::ptr::null::<libc::c_void>(),
      0usize,
      LANDLOCK_CREATE_RULESET_VERSION as u32,
    ) as i32;

    abi_version
  }
}
