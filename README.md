# beluga-ext-github

A Beluga extension that provides GitHub tools via a GitHub App installation.

## Tools

- `github_push_to_branch` — Commit and push file changes to a branch (agent/ prefix required)
- `github_create_pull_request` — Open a pull request from an agent branch
- `github_comment_on_pull_request` — Add a comment to a PR
- `github_update_pull_request` — Update a PR's title or description
- `github_list_pull_requests` — List PRs on a repository

## Install

```bash
beluga extend install github.com/aspectrr/beluga-ext-github
```

Or for local development:

```bash
beluga extend install /path/to/beluga-ext-github
```

## Config

```yaml
extensions:
  github:
    enabled: true
    app_id: 123456
    private_key: "${GITHUB_PRIVATE_KEY}"
    # private_key_path: "/path/to/key.pem"  # alternative: read from file
    # base_url: "https://api.github.com"    # default; use for GHES
    branch_prefix: "agent/"
    protected_refs: "main,master,release/*"
```

### GitHub App Setup

1. Create a GitHub App in your org/user settings
2. Give it these permissions:
   - **Contents**: Read & Write (for Git Data API)
   - **Pull requests**: Read & Write
   - **Issues**: Write (for PR comments via Issues API)
3. Install the app on the repositories the agent needs access to
4. Generate a private key and set `GITHUB_PRIVATE_KEY` env var

## Development

This extension depends on Beluga's core packages via a `replace` directive:

```
replace github.com/aspectrr/beluga => ../beluga
```

```bash
go mod tidy
go build .
```

## Safety

- Agent branches must start with `agent/` (configurable)
- Protected branches (main, master, release/*) can never be pushed to
- PRs must be reviewed and merged by a human
- Only PRs from agent branches can be updated by the agent
