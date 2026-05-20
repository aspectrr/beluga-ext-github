package github

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/collinpfeifer/beluga/ext/tools"
)

// GitHubToolConfig holds configuration for GitHub tool safety constraints.
type GitHubToolConfig struct {
	BranchPrefix  string   // required prefix for agent branches (e.g. "agent/")
	ProtectedRefs []string // globs of protected branch names (e.g. ["main", "master", "release/*"])
}

// isProtectedRef checks if a branch name matches any protected ref pattern.
func (c *GitHubToolConfig) isProtectedRef(branch string) bool {
	for _, pattern := range c.ProtectedRefs {
		matched, err := filepath.Match(pattern, branch)
		if err == nil && matched {
			return true
		}
		if branch == pattern {
			return true
		}
	}
	return false
}

// validateAgentBranch checks that a branch name is allowed for agent use.
func (c *GitHubToolConfig) validateAgentBranch(branch string) error {
	if c.isProtectedRef(branch) {
		return fmt.Errorf("branch %q is protected — the agent cannot push to protected branches (main, master, release/*)", branch)
	}
	if c.BranchPrefix != "" && !strings.HasPrefix(branch, c.BranchPrefix) {
		return fmt.Errorf("branch %q must start with %q — agent branches must be namespaced to distinguish them from human branches", branch, c.BranchPrefix)
	}
	return nil
}

// --- github_push_to_branch ---

type pushToBranchTool struct {
	client *Client
	config GitHubToolConfig
}

func (t *pushToBranchTool) Definition() tools.ToolDef {
	return tools.ToolDef{
		Name: "github_push_to_branch",
		Description: "Commit and push file changes to a branch in a GitHub repository. " +
			"The branch MUST start with the agent prefix (default: \"agent/\"). " +
			"Protected branches (main, master, release/*) are NEVER allowed. " +
			"If the branch doesn't exist, it is created from the base branch. " +
			"Use this to stage your fix, then create a PR for review.",
		Parameters: json.RawMessage(`{
			"type": "object",
			"properties": {
				"owner":       {"type": "string", "description": "Repository owner (user or org)"},
				"repo":        {"type": "string", "description": "Repository name"},
				"branch":      {"type": "string", "description": "Target branch name (must start with agent/)"},
				"base_branch": {"type": "string", "description": "Branch to create from if target doesn't exist (default: main)"},
				"message":     {"type": "string", "description": "Git commit message"},
				"files": {
					"type": "array",
					"items": {
						"type": "object",
						"properties": {
							"path":    {"type": "string", "description": "File path within the repo"},
							"content": {"type": "string", "description": "Full file content (replaces entire file)"}
						},
						"required": ["path", "content"]
					},
					"description": "Files to create or update"
				}
			},
			"required": ["owner", "repo", "branch", "message", "files"]
		}`),
	}
}

func (t *pushToBranchTool) Execute(ctx context.Context, args json.RawMessage, _ tools.ToolContext) (json.RawMessage, error) {
	if os.Getenv("BELUGA_DRY_RUN") == "true" {
		return json.Marshal(map[string]interface{}{
			"status":  "dry_run",
			"message": "would push files to branch",
		})
	}

	if t.client == nil {
		return nil, fmt.Errorf("github tools not available: no client configured")
	}

	var params struct {
		Owner      string `json:"owner"`
		Repo       string `json:"repo"`
		Branch     string `json:"branch"`
		BaseBranch string `json:"base_branch"`
		Message    string `json:"message"`
		Files      []struct {
			Path    string `json:"path"`
			Content string `json:"content"`
		} `json:"files"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return nil, fmt.Errorf("parsing args: %w", err)
	}

	if params.Owner == "" || params.Repo == "" {
		return nil, fmt.Errorf("owner and repo are required")
	}
	if params.Branch == "" {
		return nil, fmt.Errorf("branch is required")
	}
	if params.Message == "" {
		return nil, fmt.Errorf("message is required")
	}
	if len(params.Files) == 0 {
		return nil, fmt.Errorf("at least one file is required")
	}

	if err := t.config.validateAgentBranch(params.Branch); err != nil {
		return nil, err
	}

	if params.BaseBranch == "" {
		params.BaseBranch = "main"
	}

	installID, err := t.client.GetInstallationForRepo(ctx, params.Owner, params.Repo)
	if err != nil {
		return nil, fmt.Errorf("finding GitHub App installation for %s/%s: %w", params.Owner, params.Repo, err)
	}

	// Check if the branch already exists.
	_, err = t.client.GetBranchSHA(ctx, installID, params.Owner, params.Repo, params.Branch)
	if err != nil {
		// Branch doesn't exist — create it from the base branch.
		baseSHA, err := t.client.GetBranchSHA(ctx, installID, params.Owner, params.Repo, params.BaseBranch)
		if err != nil {
			return nil, fmt.Errorf("getting base branch %q SHA: %w", params.BaseBranch, err)
		}
		if err := t.client.CreateRef(ctx, installID, params.Owner, params.Repo, params.Branch, baseSHA); err != nil {
			return nil, fmt.Errorf("creating branch %q from %q: %w", params.Branch, params.BaseBranch, err)
		}
	}

	files := make(map[string]string, len(params.Files))
	for _, f := range params.Files {
		if f.Path == "" {
			return nil, fmt.Errorf("file path cannot be empty")
		}
		files[f.Path] = f.Content
	}

	commitSHA, err := t.client.CreateCommit(ctx, installID, params.Owner, params.Repo, params.Branch, params.Message, files)
	if err != nil {
		return nil, fmt.Errorf("creating commit: %w", err)
	}

	return json.Marshal(map[string]interface{}{
		"status":     "pushed",
		"owner":      params.Owner,
		"repo":       params.Repo,
		"branch":     params.Branch,
		"commit_sha": commitSHA,
		"files":      len(files),
		"message":    fmt.Sprintf("Pushed %d file(s) to %s/%s on branch %s. Use github_create_pull_request to open a PR for review.", len(files), params.Owner, params.Repo, params.Branch),
	})
}

// --- github_create_pull_request ---

type createPRTool struct {
	client *Client
	config GitHubToolConfig
}

func (t *createPRTool) Definition() tools.ToolDef {
	return tools.ToolDef{
		Name: "github_create_pull_request",
		Description: "Open a pull request on a GitHub repository. " +
			"The head branch MUST start with the agent prefix (default: \"agent/\"). " +
			"Protected branches (main, master, release/*) cannot be used as the head branch. " +
			"PRs created by the agent must be reviewed and merged by a human.",
		Parameters: json.RawMessage(`{
			"type": "object",
			"properties": {
				"owner":  {"type": "string", "description": "Repository owner (user or org)"},
				"repo":   {"type": "string", "description": "Repository name"},
				"title":  {"type": "string", "description": "Pull request title"},
				"body":   {"type": "string", "description": "Pull request body (markdown). Include a summary of changes, testing performed, and any notes for reviewers."},
				"head":   {"type": "string", "description": "Source branch name (the agent's branch with changes)"},
				"base":   {"type": "string", "description": "Target branch to merge into (e.g. \"main\")"},
				"draft":  {"type": "boolean", "description": "Create as draft PR (default: false)"}
			},
			"required": ["owner", "repo", "title", "head", "base"]
		}`),
	}
}

func (t *createPRTool) Execute(ctx context.Context, args json.RawMessage, _ tools.ToolContext) (json.RawMessage, error) {
	if os.Getenv("BELUGA_DRY_RUN") == "true" {
		return json.Marshal(map[string]interface{}{
			"status":  "dry_run",
			"message": "would create pull request",
		})
	}

	if t.client == nil {
		return nil, fmt.Errorf("github tools not available: no client configured")
	}

	var params struct {
		Owner string `json:"owner"`
		Repo  string `json:"repo"`
		Title string `json:"title"`
		Body  string `json:"body"`
		Head  string `json:"head"`
		Base  string `json:"base"`
		Draft bool   `json:"draft"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return nil, fmt.Errorf("parsing args: %w", err)
	}

	if params.Owner == "" || params.Repo == "" {
		return nil, fmt.Errorf("owner and repo are required")
	}
	if params.Title == "" {
		return nil, fmt.Errorf("title is required")
	}
	if params.Head == "" || params.Base == "" {
		return nil, fmt.Errorf("head and base branches are required")
	}

	if err := t.config.validateAgentBranch(params.Head); err != nil {
		return nil, fmt.Errorf("invalid head branch: %w", err)
	}

	if strings.HasPrefix(params.Base, t.config.BranchPrefix) {
		return nil, fmt.Errorf("base branch %q is an agent branch — PRs should target a non-agent branch like main", params.Base)
	}

	installID, err := t.client.GetInstallationForRepo(ctx, params.Owner, params.Repo)
	if err != nil {
		return nil, fmt.Errorf("finding GitHub App installation for %s/%s: %w", params.Owner, params.Repo, err)
	}

	pr, err := t.client.CreatePullRequest(ctx, installID, params.Owner, params.Repo, CreatePROptions{
		Title: params.Title,
		Body:  params.Body,
		Head:  params.Head,
		Base:  params.Base,
		Draft: params.Draft,
	})
	if err != nil {
		return nil, fmt.Errorf("creating PR: %w", err)
	}

	return json.Marshal(map[string]interface{}{
		"status":      "created",
		"pr_number":   pr.Number,
		"pr_url":      pr.HTMLURL,
		"pr_title":    pr.Title,
		"pr_state":    pr.State,
		"draft":       pr.Draft,
		"head_branch": pr.Head.Ref,
		"base_branch": pr.Base.Ref,
		"message":     fmt.Sprintf("Pull request #%d created: %s. A human must review and merge this PR.", pr.Number, pr.HTMLURL),
	})
}

// --- github_comment_on_pull_request ---

type commentOnPRTool struct {
	client *Client
	config GitHubToolConfig
}

func (t *commentOnPRTool) Definition() tools.ToolDef {
	return tools.ToolDef{
		Name: "github_comment_on_pull_request",
		Description: "Add a comment to a pull request. " +
			"Use this to provide context about your changes, respond to review feedback, " +
			"or communicate with reviewers. Comments are attributed to the app bot identity.",
		Parameters: json.RawMessage(`{
			"type": "object",
			"properties": {
				"owner":       {"type": "string", "description": "Repository owner (user or org)"},
				"repo":        {"type": "string", "description": "Repository name"},
				"pull_number": {"type": "integer", "description": "Pull request number"},
				"body":        {"type": "string", "description": "Comment body (markdown)"}
			},
			"required": ["owner", "repo", "pull_number", "body"]
		}`),
	}
}

func (t *commentOnPRTool) Execute(ctx context.Context, args json.RawMessage, _ tools.ToolContext) (json.RawMessage, error) {
	if os.Getenv("BELUGA_DRY_RUN") == "true" {
		return json.Marshal(map[string]interface{}{
			"status":  "dry_run",
			"message": "would comment on pull request",
		})
	}

	if t.client == nil {
		return nil, fmt.Errorf("github tools not available: no client configured")
	}

	var params struct {
		Owner      string `json:"owner"`
		Repo       string `json:"repo"`
		PullNumber int    `json:"pull_number"`
		Body       string `json:"body"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return nil, fmt.Errorf("parsing args: %w", err)
	}

	if params.Owner == "" || params.Repo == "" {
		return nil, fmt.Errorf("owner and repo are required")
	}
	if params.PullNumber <= 0 {
		return nil, fmt.Errorf("pull_number must be a positive integer")
	}
	if params.Body == "" {
		return nil, fmt.Errorf("body is required")
	}

	installID, err := t.client.GetInstallationForRepo(ctx, params.Owner, params.Repo)
	if err != nil {
		return nil, fmt.Errorf("finding GitHub App installation for %s/%s: %w", params.Owner, params.Repo, err)
	}

	comment, err := t.client.CommentOnPullRequest(ctx, installID, params.Owner, params.Repo, params.PullNumber, params.Body)
	if err != nil {
		return nil, fmt.Errorf("creating comment: %w", err)
	}

	return json.Marshal(map[string]interface{}{
		"status":     "commented",
		"comment_id": comment.ID,
		"pr_number":  params.PullNumber,
		"message":    fmt.Sprintf("Comment added to PR #%d in %s/%s", params.PullNumber, params.Owner, params.Repo),
	})
}

// --- github_update_pull_request ---

type updatePRTool struct {
	client *Client
	config GitHubToolConfig
}

func (t *updatePRTool) Definition() tools.ToolDef {
	return tools.ToolDef{
		Name: "github_update_pull_request",
		Description: "Update an existing pull request's title or description. " +
			"Only PRs from agent branches can be updated — the head branch must start with the agent prefix. " +
			"To push new commits to an existing PR, use github_push_to_branch with the same branch name.",
		Parameters: json.RawMessage(`{
			"type": "object",
			"properties": {
				"owner":       {"type": "string", "description": "Repository owner (user or org)"},
				"repo":        {"type": "string", "description": "Repository name"},
				"pull_number": {"type": "integer", "description": "Pull request number"},
				"title":       {"type": "string", "description": "New PR title (optional)"},
				"body":        {"type": "string", "description": "New PR body in markdown (optional)"}
			},
			"required": ["owner", "repo", "pull_number"]
		}`),
	}
}

func (t *updatePRTool) Execute(ctx context.Context, args json.RawMessage, _ tools.ToolContext) (json.RawMessage, error) {
	if os.Getenv("BELUGA_DRY_RUN") == "true" {
		return json.Marshal(map[string]interface{}{
			"status":  "dry_run",
			"message": "would update pull request",
		})
	}

	if t.client == nil {
		return nil, fmt.Errorf("github tools not available: no client configured")
	}

	var params struct {
		Owner      string `json:"owner"`
		Repo       string `json:"repo"`
		PullNumber int    `json:"pull_number"`
		Title      string `json:"title"`
		Body       string `json:"body"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return nil, fmt.Errorf("parsing args: %w", err)
	}

	if params.Owner == "" || params.Repo == "" {
		return nil, fmt.Errorf("owner and repo are required")
	}
	if params.PullNumber <= 0 {
		return nil, fmt.Errorf("pull_number must be a positive integer")
	}
	if params.Title == "" && params.Body == "" {
		return nil, fmt.Errorf("at least one of title or body must be provided")
	}

	installID, err := t.client.GetInstallationForRepo(ctx, params.Owner, params.Repo)
	if err != nil {
		return nil, fmt.Errorf("finding GitHub App installation for %s/%s: %w", params.Owner, params.Repo, err)
	}

	// Fetch the existing PR to verify the head branch is an agent branch.
	pr, err := t.client.GetPullRequest(ctx, installID, params.Owner, params.Repo, params.PullNumber)
	if err != nil {
		return nil, fmt.Errorf("fetching PR #%d: %w", params.PullNumber, err)
	}

	if !strings.HasPrefix(pr.Head.Ref, t.config.BranchPrefix) {
		return nil, fmt.Errorf("cannot update PR #%d — head branch %q is not an agent branch (must start with %q). Only PRs created by the agent can be updated.", params.PullNumber, pr.Head.Ref, t.config.BranchPrefix)
	}

	updatedPR, err := t.client.UpdatePullRequest(ctx, installID, params.Owner, params.Repo, params.PullNumber, params.Title, params.Body)
	if err != nil {
		return nil, fmt.Errorf("updating PR: %w", err)
	}

	return json.Marshal(map[string]interface{}{
		"status":    "updated",
		"pr_number": updatedPR.Number,
		"pr_title":  updatedPR.Title,
		"pr_url":    updatedPR.HTMLURL,
		"message":   fmt.Sprintf("PR #%d updated in %s/%s", params.PullNumber, params.Owner, params.Repo),
	})
}

// --- github_list_pull_requests ---

type listPRsTool struct {
	client *Client
	config GitHubToolConfig
}

func (t *listPRsTool) Definition() tools.ToolDef {
	return tools.ToolDef{
		Name: "github_list_pull_requests",
		Description: "List pull requests on a GitHub repository. " +
			"Returns PR number, title, state, head/base branches, and URL. " +
			"Useful for checking if a PR already exists or finding PRs to comment on.",
		Parameters: json.RawMessage(`{
			"type": "object",
			"properties": {
				"owner": {"type": "string", "description": "Repository owner (user or org)"},
				"repo":  {"type": "string", "description": "Repository name"},
				"state": {"type": "string", "enum": ["open", "closed", "all"], "description": "PR state filter (default: open)"},
				"head":  {"type": "string", "description": "Filter by head branch (e.g. 'agent/fix-auth')"}
			},
			"required": ["owner", "repo"]
		}`),
	}
}

func (t *listPRsTool) Execute(ctx context.Context, args json.RawMessage, _ tools.ToolContext) (json.RawMessage, error) {
	if os.Getenv("BELUGA_DRY_RUN") == "true" {
		return json.Marshal(map[string]interface{}{
			"status":  "dry_run",
			"count":   0,
			"pr_list": []struct{}{},
		})
	}

	if t.client == nil {
		return nil, fmt.Errorf("github tools not available: no client configured")
	}

	var params struct {
		Owner string `json:"owner"`
		Repo  string `json:"repo"`
		State string `json:"state"`
		Head  string `json:"head"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return nil, fmt.Errorf("parsing args: %w", err)
	}

	if params.Owner == "" || params.Repo == "" {
		return nil, fmt.Errorf("owner and repo are required")
	}
	if params.State == "" {
		params.State = "open"
	}

	installID, err := t.client.GetInstallationForRepo(ctx, params.Owner, params.Repo)
	if err != nil {
		return nil, fmt.Errorf("finding GitHub App installation for %s/%s: %w", params.Owner, params.Repo, err)
	}

	prs, err := t.client.ListPullRequests(ctx, installID, params.Owner, params.Repo, params.State, params.Head)
	if err != nil {
		return nil, fmt.Errorf("listing PRs: %w", err)
	}

	type PRSummary struct {
		Number     int    `json:"number"`
		Title      string `json:"title"`
		State      string `json:"state"`
		HeadBranch string `json:"head_branch"`
		BaseBranch string `json:"base_branch"`
		HTMLURL    string `json:"html_url"`
		Draft      bool   `json:"draft"`
		Author     string `json:"author"`
	}

	summaries := make([]PRSummary, 0, len(prs))
	for _, pr := range prs {
		summaries = append(summaries, PRSummary{
			Number:     pr.Number,
			Title:      pr.Title,
			State:      pr.State,
			HeadBranch: pr.Head.Ref,
			BaseBranch: pr.Base.Ref,
			HTMLURL:    pr.HTMLURL,
			Draft:      pr.Draft,
			Author:     pr.User.Login,
		})
	}

	return json.Marshal(map[string]interface{}{
		"count":   len(summaries),
		"pr_list": summaries,
	})
}

// registerTools registers all GitHub tools with the given registry.
func registerTools(registry *tools.Registry, client *Client, cfg GitHubToolConfig) error {
	toolList := []tools.Tool{
		&pushToBranchTool{client: client, config: cfg},
		&createPRTool{client: client, config: cfg},
		&commentOnPRTool{client: client, config: cfg},
		&updatePRTool{client: client, config: cfg},
		&listPRsTool{client: client, config: cfg},
	}
	for _, tool := range toolList {
		if err := registry.Register(tool); err != nil {
			return err
		}
	}
	return nil
}
