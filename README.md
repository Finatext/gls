# gls

gls (gitleaks-support) enhances the development of gitleaks rules and allowlists, and extends gitleaks features with:

- Support for multiple global and rule-specific allowlists.
- Ability to handle multiple configuration files.

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
