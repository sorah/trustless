// `trustless run` — auto-infer subdomain name and run a command behind the HTTPS proxy

#[derive(clap::Args, Debug, Clone)]
pub struct RunArgs {
    /// Profile name to select which provider's domains to use
    #[arg(long, env = "TRUSTLESS_PROFILE")]
    profile: Option<String>,

    /// Domain suffix to use (when provider has multiple wildcard domains)
    #[arg(long)]
    domain: Option<String>,

    /// Use a fixed port instead of ephemeral allocation
    #[arg(long)]
    port: Option<u16>,

    /// Disable framework-specific flag injection (e.g. --port, --host for Vite/Astro)
    #[arg(long)]
    no_framework: bool,

    /// Command line to execute.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    command: Vec<std::ffi::OsString>,
}

pub fn run(args: &RunArgs) -> anyhow::Result<()> {
    if super::exec::should_skip() {
        return super::exec::skip_exec(&args.command);
    }
    let hostname_spec = infer_project_name()?.with_worktree(detect_worktree_prefix());
    match &hostname_spec {
        crate::domain::HostnameSpec::Label(s) => {
            eprintln!("trustless: inferred subdomain '{}'", s);
        }
        crate::domain::HostnameSpec::LabelWithWorktree { label, worktree } => {
            eprintln!(
                "trustless: inferred subdomain '{}' with worktree '{}'",
                label, worktree
            );
        }
        crate::domain::HostnameSpec::Full(h) => {
            eprintln!("trustless: using hostname '{}'", h);
        }
    }
    let params = super::exec::ExecParams {
        hostname_spec,
        profile: args.profile.clone(),
        domain: args.domain.clone(),
        port: args.port,
        no_framework: args.no_framework,
        command: args.command.clone(),
    };
    super::exec::run_exec(params)
}

fn infer_project_name() -> anyhow::Result<crate::domain::HostnameSpec> {
    let cwd = std::env::current_dir()?;

    // 1. .trustless.json (highest priority)
    if let Some(tj) = find_trustless_json(&cwd) {
        match tj.name {
            NameOptions::Domain { domain } => {
                crate::domain::validate_hostname(&domain)?;
                return Ok(crate::domain::HostnameSpec::Full(domain));
            }
            NameOptions::Label { name } => {
                return Ok(crate::domain::HostnameSpec::Label(name));
            }
        }
    }

    // 2. Walk up looking for package.json
    if let Some(name) = find_package_json_name(&cwd)
        && let Some(sanitized) = crate::domain::sanitize_label(&name)
    {
        return Ok(crate::domain::HostnameSpec::Label(sanitized));
    }

    // 3. Git repo root directory name
    if let Some(git_root) = find_git_root(&cwd)
        && let Some(basename) = git_root.file_name().and_then(|n| n.to_str())
        && let Some(sanitized) = crate::domain::sanitize_label(basename)
    {
        return Ok(crate::domain::HostnameSpec::Label(sanitized));
    }

    // 4. Current directory basename
    if let Some(basename) = cwd.file_name().and_then(|n| n.to_str())
        && let Some(sanitized) = crate::domain::sanitize_label(basename)
    {
        return Ok(crate::domain::HostnameSpec::Label(sanitized));
    }

    anyhow::bail!(
        "could not infer a project name from .trustless.json, package.json, git root, or directory name"
    )
}

#[cfg(unix)]
fn find_in_ancestors<T>(
    start_dir: &std::path::Path,
    mut probe: impl FnMut(&std::path::Path) -> Option<T>,
) -> Option<T> {
    use std::os::unix::fs::MetadataExt as _;
    let start_dev = std::fs::metadata(start_dir).ok()?.dev();
    let mut dir = start_dir.to_path_buf();
    loop {
        if let Some(result) = probe(&dir) {
            return Some(result);
        }
        if !dir.pop() {
            break;
        }
        if let Ok(meta) = std::fs::metadata(&dir) {
            if meta.dev() != start_dev {
                break;
            }
        } else {
            break;
        }
    }
    None
}

#[derive(serde::Deserialize)]
struct TrustlessJson {
    #[serde(flatten)]
    name: NameOptions,
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum NameOptions {
    Domain { domain: String },
    Label { name: String },
}

fn find_trustless_json(start_dir: &std::path::Path) -> Option<TrustlessJson> {
    find_in_ancestors(start_dir, |dir| {
        let raw = std::fs::read_to_string(dir.join(".trustless.json")).ok()?;
        serde_json::from_str::<TrustlessJson>(&raw).ok()
    })
}

#[derive(serde::Deserialize)]
struct PackageJson {
    #[serde(default)]
    name: Option<String>,
}

/// Walk up from `start_dir` looking for a package.json with a `name` field.
/// Returns the name with `@scope/` prefix stripped, or None.
fn find_package_json_name(start_dir: &std::path::Path) -> Option<String> {
    find_in_ancestors(start_dir, |dir| {
        let raw = std::fs::read_to_string(dir.join("package.json")).ok()?;
        let pkg: PackageJson = serde_json::from_str(&raw).ok()?;
        let name = pkg.name?;
        (!name.is_empty()).then(|| strip_npm_scope(&name).to_string())
    })
}

fn strip_npm_scope(name: &str) -> &str {
    if let Some(rest) = name.strip_prefix('@') {
        match rest.find('/') {
            Some(i) => &rest[i + 1..],
            None => name,
        }
    } else {
        name
    }
}

/// Find the git repo root: try `git rev-parse --show-toplevel`, then walk up for `.git` dir.
fn find_git_root(start_dir: &std::path::Path) -> Option<std::path::PathBuf> {
    // Try git CLI
    if let Ok(output) = std::process::Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .current_dir(start_dir)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .stdin(std::process::Stdio::null())
        .output()
        && output.status.success()
    {
        let toplevel = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !toplevel.is_empty() {
            return Some(std::path::PathBuf::from(toplevel));
        }
    }

    // Fallback: walk up looking for .git directory
    find_in_ancestors(start_dir, |dir| {
        let meta = std::fs::metadata(dir.join(".git")).ok()?;
        (meta.is_dir() || meta.is_file()).then(|| dir.to_path_buf())
    })
}

const DEFAULT_BRANCHES: &[&str] = &["main", "master"];

/// Convert a branch name into a worktree prefix label.
/// Uses only the last segment after `/` (e.g. `feature/auth` → `auth`).
/// Returns `None` for default branches, detached HEAD, or names that sanitize to empty.
fn branch_to_prefix(branch: &str) -> Option<String> {
    if branch.is_empty() || branch == "HEAD" || DEFAULT_BRANCHES.contains(&branch) {
        return None;
    }
    let last_segment = branch.rsplit('/').next().unwrap_or(branch);
    crate::domain::sanitize_label(last_segment)
}

/// Detect if the current directory is inside a multi-worktree git repo and return
/// the current branch name as a sanitized prefix for hostname composition.
fn detect_worktree_prefix() -> Option<String> {
    let cwd = std::env::current_dir().ok()?;
    detect_worktree_via_cli(&cwd).unwrap_or_else(|| detect_worktree_via_filesystem(&cwd))
}

/// Use git CLI to detect worktree prefix. Returns:
///   - `Some(Some(prefix))` if in a non-default-branch worktree
///   - `Some(None)` if not in a worktree setup, or on main/master
///   - `None` if git CLI is unavailable (caller should try fallback)
fn detect_worktree_via_cli(cwd: &std::path::Path) -> Option<Option<String>> {
    let list_output = std::process::Command::new("git")
        .args(["worktree", "list", "--porcelain"])
        .current_dir(cwd)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .stdin(std::process::Stdio::null())
        .output()
        .ok()?;
    if !list_output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&list_output.stdout);
    let worktree_count = stdout
        .lines()
        .filter(|l| l.starts_with("worktree "))
        .count();
    if worktree_count <= 1 {
        return Some(None);
    }

    let branch_output = std::process::Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .current_dir(cwd)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .stdin(std::process::Stdio::null())
        .output()
        .ok()?;
    if !branch_output.status.success() {
        return Some(None);
    }

    let branch = String::from_utf8_lossy(&branch_output.stdout)
        .trim()
        .to_string();
    Some(branch_to_prefix(&branch))
}

/// Fallback worktree detection when git CLI is unavailable. Walks up from `cwd`
/// looking for a `.git` file (worktrees have a file, not a directory) and reads
/// the branch name from the gitdir's HEAD file.
fn detect_worktree_via_filesystem(cwd: &std::path::Path) -> Option<String> {
    find_in_ancestors(cwd, |dir| {
        let git_path = dir.join(".git");
        let meta = std::fs::metadata(&git_path).ok()?;
        if meta.is_dir() {
            // Regular .git directory — not a worktree, stop searching
            return Some(None);
        }
        if !meta.is_file() {
            return None;
        }
        let content = std::fs::read_to_string(&git_path).ok()?;
        let gitdir_line = content.trim();
        let gitdir = gitdir_line.strip_prefix("gitdir:")?;
        let gitdir = gitdir.trim();

        // Only treat as a worktree if gitdir points into a /worktrees/ path.
        // Submodules point to /modules/ instead.
        if !is_worktree_gitdir(gitdir) {
            return Some(None);
        }

        let gitdir_path = if std::path::Path::new(gitdir).is_absolute() {
            std::path::PathBuf::from(gitdir)
        } else {
            dir.join(gitdir)
        };
        let branch = read_branch_from_head(&gitdir_path)?;
        Some(branch_to_prefix(&branch))
    })?
}

/// Check if a gitdir path ends with `/worktrees/<name>` (not `/modules/<name>`).
fn is_worktree_gitdir(gitdir: &str) -> bool {
    let parts: Vec<&str> = gitdir.split('/').collect();
    parts.len() >= 2 && parts[parts.len() - 2] == "worktrees" && !parts[parts.len() - 1].is_empty()
}

/// Read the current branch name from a gitdir's HEAD file.
/// Returns `None` for detached HEAD or unreadable files.
fn read_branch_from_head(gitdir: &std::path::Path) -> Option<String> {
    let head = std::fs::read_to_string(gitdir.join("HEAD")).ok()?;
    let head = head.trim();
    let branch = head.strip_prefix("ref: refs/heads/")?;
    Some(branch.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_npm_scope() {
        assert_eq!(strip_npm_scope("@scope/myapp"), "myapp");
        assert_eq!(strip_npm_scope("@org/my-app"), "my-app");
        assert_eq!(strip_npm_scope("myapp"), "myapp");
        assert_eq!(strip_npm_scope("@broken"), "@broken");
        assert_eq!(strip_npm_scope(""), "");
    }

    #[test]
    fn test_find_package_json_name() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = serde_json::json!({ "name": "@scope/my_app" });
        std::fs::write(dir.path().join("package.json"), pkg.to_string()).unwrap();

        let name = find_package_json_name(dir.path()).unwrap();
        assert_eq!(name, "my_app");
    }

    #[test]
    fn test_find_package_json_name_walks_up() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("a").join("b");
        std::fs::create_dir_all(&sub).unwrap();
        let pkg = serde_json::json!({ "name": "root-pkg" });
        std::fs::write(dir.path().join("package.json"), pkg.to_string()).unwrap();

        let name = find_package_json_name(&sub).unwrap();
        assert_eq!(name, "root-pkg");
    }

    #[test]
    fn test_find_package_json_name_none() {
        let dir = tempfile::tempdir().unwrap();
        assert!(find_package_json_name(dir.path()).is_none());
    }

    #[test]
    fn test_find_git_root_with_dotgit_dir() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("src");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::create_dir_all(dir.path().join(".git")).unwrap();

        let root = find_git_root(&sub).unwrap();
        assert_eq!(root, dir.path());
    }

    #[test]
    fn test_find_trustless_json_domain() {
        let dir = tempfile::tempdir().unwrap();
        let tj = serde_json::json!({ "domain": "myapp.dev.invalid" });
        std::fs::write(dir.path().join(".trustless.json"), tj.to_string()).unwrap();

        let result = find_trustless_json(dir.path()).unwrap();
        match result.name {
            NameOptions::Domain { domain } => assert_eq!(domain, "myapp.dev.invalid"),
            NameOptions::Label { .. } => panic!("expected Domain variant"),
        }
    }

    #[test]
    fn test_find_trustless_json_label() {
        let dir = tempfile::tempdir().unwrap();
        let tj = serde_json::json!({ "name": "my-app" });
        std::fs::write(dir.path().join(".trustless.json"), tj.to_string()).unwrap();

        let result = find_trustless_json(dir.path()).unwrap();
        match result.name {
            NameOptions::Label { name } => assert_eq!(name, "my-app"),
            NameOptions::Domain { .. } => panic!("expected Label variant"),
        }
    }

    #[test]
    fn test_find_trustless_json_walks_up() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("a").join("b");
        std::fs::create_dir_all(&sub).unwrap();
        let tj = serde_json::json!({ "name": "parent-app" });
        std::fs::write(dir.path().join(".trustless.json"), tj.to_string()).unwrap();

        let result = find_trustless_json(&sub).unwrap();
        match result.name {
            NameOptions::Label { name } => assert_eq!(name, "parent-app"),
            NameOptions::Domain { .. } => panic!("expected Label variant"),
        }
    }

    #[test]
    fn test_find_trustless_json_not_found() {
        let dir = tempfile::tempdir().unwrap();
        assert!(find_trustless_json(dir.path()).is_none());
    }

    #[test]
    fn test_trustless_json_priority_over_package_json() {
        let dir = tempfile::tempdir().unwrap();
        let tj = serde_json::json!({ "domain": "custom.dev.invalid" });
        std::fs::write(dir.path().join(".trustless.json"), tj.to_string()).unwrap();
        let pkg = serde_json::json!({ "name": "pkg-name" });
        std::fs::write(dir.path().join("package.json"), pkg.to_string()).unwrap();

        // find_trustless_json should find the .trustless.json
        let result = find_trustless_json(dir.path()).unwrap();
        match result.name {
            NameOptions::Domain { domain } => assert_eq!(domain, "custom.dev.invalid"),
            NameOptions::Label { .. } => panic!("expected Domain variant"),
        }

        // package.json should also be findable independently
        let pkg_name = find_package_json_name(dir.path()).unwrap();
        assert_eq!(pkg_name, "pkg-name");
    }

    #[test]
    fn test_find_in_ancestors_stops_at_root() {
        let dir = tempfile::tempdir().unwrap();
        let deep = dir.path().join("a").join("b").join("c");
        std::fs::create_dir_all(&deep).unwrap();

        // No file exists anywhere, should return None without panicking
        let result = find_in_ancestors(&deep, |d| {
            std::fs::read_to_string(d.join("nonexistent.marker")).ok()
        });
        assert!(result.is_none());
    }

    #[test]
    fn test_branch_to_prefix() {
        assert_eq!(branch_to_prefix("feature/auth"), Some("auth".to_string()));
        assert_eq!(branch_to_prefix("fix/big-bug"), Some("big-bug".to_string()));
        assert_eq!(branch_to_prefix("my-branch"), Some("my-branch".to_string()));
        assert_eq!(branch_to_prefix("main"), None);
        assert_eq!(branch_to_prefix("master"), None);
        assert_eq!(branch_to_prefix("HEAD"), None);
        assert_eq!(branch_to_prefix(""), None);
        // Deeply nested
        assert_eq!(branch_to_prefix("a/b/c/my-fix"), Some("my-fix".to_string()));
    }

    #[test]
    fn test_is_worktree_gitdir() {
        assert!(is_worktree_gitdir(
            "/home/user/repo/.git/worktrees/my-branch"
        ));
        assert!(is_worktree_gitdir("../.git/worktrees/branch"));
        assert!(!is_worktree_gitdir("/home/user/repo/.git/modules/sub"));
        assert!(!is_worktree_gitdir("/home/user/repo/.git"));
        assert!(!is_worktree_gitdir("/home/user/repo/.git/worktrees/"));
    }

    #[test]
    fn test_detect_worktree_via_filesystem_with_worktree() {
        let dir = tempfile::tempdir().unwrap();
        let main_git = dir.path().join("main-repo").join(".git");
        std::fs::create_dir_all(&main_git).unwrap();

        // Create a worktree gitdir
        let wt_gitdir = main_git.join("worktrees").join("my-branch");
        std::fs::create_dir_all(&wt_gitdir).unwrap();
        std::fs::write(wt_gitdir.join("HEAD"), "ref: refs/heads/feature/login\n").unwrap();

        // Create the worktree checkout directory with a .git file
        let wt_checkout = dir.path().join("wt-checkout");
        std::fs::create_dir_all(&wt_checkout).unwrap();
        std::fs::write(
            wt_checkout.join(".git"),
            format!("gitdir: {}\n", wt_gitdir.display()),
        )
        .unwrap();

        let prefix = detect_worktree_via_filesystem(&wt_checkout);
        assert_eq!(prefix, Some("login".to_string()));
    }

    #[test]
    fn test_detect_worktree_via_filesystem_regular_repo() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".git")).unwrap();

        // Regular .git directory → not a worktree
        let prefix = detect_worktree_via_filesystem(dir.path());
        assert_eq!(prefix, None);
    }

    #[test]
    fn test_detect_worktree_via_filesystem_submodule() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("submod");
        std::fs::create_dir_all(&sub).unwrap();
        // Submodules point to /modules/, not /worktrees/
        std::fs::write(sub.join(".git"), "gitdir: ../.git/modules/submod\n").unwrap();

        let prefix = detect_worktree_via_filesystem(&sub);
        assert_eq!(prefix, None);
    }

    #[test]
    fn test_detect_worktree_via_filesystem_default_branch() {
        let dir = tempfile::tempdir().unwrap();
        let main_git = dir.path().join("main-repo").join(".git");
        std::fs::create_dir_all(&main_git).unwrap();

        let wt_gitdir = main_git.join("worktrees").join("main-wt");
        std::fs::create_dir_all(&wt_gitdir).unwrap();
        std::fs::write(wt_gitdir.join("HEAD"), "ref: refs/heads/main\n").unwrap();

        let wt_checkout = dir.path().join("wt-main");
        std::fs::create_dir_all(&wt_checkout).unwrap();
        std::fs::write(
            wt_checkout.join(".git"),
            format!("gitdir: {}\n", wt_gitdir.display()),
        )
        .unwrap();

        // main branch → no prefix
        let prefix = detect_worktree_via_filesystem(&wt_checkout);
        assert_eq!(prefix, None);
    }

    #[test]
    fn test_read_branch_from_head() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("HEAD"), "ref: refs/heads/feature/auth\n").unwrap();
        assert_eq!(
            read_branch_from_head(dir.path()),
            Some("feature/auth".to_string())
        );

        // Detached HEAD (SHA)
        let dir2 = tempfile::tempdir().unwrap();
        std::fs::write(dir2.path().join("HEAD"), "abc123def456789\n").unwrap();
        assert_eq!(read_branch_from_head(dir2.path()), None);
    }
}
