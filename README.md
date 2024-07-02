# gls

gls (gitleaks-support) enhances the development of gitleaks rules and allowlists, and extends gitleaks features with:

- Support for multiple global and rule-specific allowlists.
- Ability to handle multiple configuration files.

## Install
### Homebrew
```
brew tap Finatext/gls https://github.com/Finatext/gls.git
brew install gls
```

Note: conflicts with `coreutils` package. Unlink `coreutils` and use the "gnubin" of `coreutils`.

### Cargo
```
cargo install --git https://github.com/Finatext/gls.git
```

## Design

Instead of using the original gitleaks allowlist feature, gls requires all allowlists to be defined in its own configuration files.

During the detection phase, gitleaks produces findings which are then filtered by gls according to its allowlist configurations.

## User Journey

There are two main phases: config development and detection.

### Config Development

To set up for development, gls provides the following CLI commands:

- `extract-allowlist`: This command extracts allowlist items from a specified gitleaks configuration file to a gls configuration file.
- `cleanup-allowlist`: This removes all allowlist items from a specified gitleaks configuration file.
- `cleanup-rule`: This removes all detection rules from a specified gitleaks configuration file.

Once the gitleaks configuration file is cleaned and the gls allowlist configuration files are set, you can validate and develop your allowlist configuration.

- `scan`: Executes the gitleaks detection command on specified git repositories using multiple threads.
- `review`: Reviews the results of the aforementioned scan (gitleaks report JSON files), including summaries, lists of findings per detection rule, and lists of results per allowlist.

For ongoing configuration development in day-to-day operations, gls also offers:

- `diff`: Compares two `gls review` result JSON files to identify differences in both allowed and confirmed findings.

### Detection

To filter the results from `gitleaks detect`:

- `apply`: Takes gls configuration files and a gitleaks detection result JSON file, and outputs the actual confirmed findings.

## Development
### Release
1. Update version of `Cargo.toml` and re-generate lock file
1. Git commit-push then create a PR and merge
1. Create a git tag with `git tag "$(cargo metadata --no-deps --format-version 1 | jq -r '"v" + .packages[0].version')"`
1. Push the git tag and wait the CI creates a GitHub Release and upload artifacts
1. Run `GITHUB_REF="refs/tags/$(cargo metadata --no-deps --format-version 1 | jq -r '"v" + .packages[0].version')" TARGET=gls .github/scripts/update_formula` to update Homebrew formula file
1. Create a PR and merge
