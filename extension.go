package github

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/aspectrr/beluga/pkg/extension"
	"github.com/aspectrr/beluga/pkg/tools"
)

// Extension implements the GitHub tools-only extension for Beluga.
// It provides tools for pushing branches, creating PRs, commenting,
// and listing PRs via a GitHub App installation.
type Extension struct {
	client *Client
	config GitHubToolConfig
	logger *slog.Logger
}

// Name returns the extension identifier.
func (e *Extension) Name() string { return "github" }

// Init parses config, creates the GitHub App client, and registers tools.
func (e *Extension) Init(ctx extension.ExtensionContext) error {
	e.logger = ctx.Logger

	var cfg struct {
		AppID          int64  `json:"app_id"`
		PrivateKeyPath string `json:"private_key_path"`
		PrivateKey     string `json:"private_key"`
		BaseURL        string `json:"base_url"`
		BranchPrefix   string `json:"branch_prefix"`
		ProtectedRefs  string `json:"protected_refs"` // comma-separated globs
	}
	if err := json.Unmarshal(ctx.Config, &cfg); err != nil {
		return fmt.Errorf("github: parsing config: %w", err)
	}

	// Resolve private key: raw content overrides file path.
	privateKey := cfg.PrivateKey
	if privateKey == "" && cfg.PrivateKeyPath != "" {
		data, err := os.ReadFile(cfg.PrivateKeyPath)
		if err != nil {
			return fmt.Errorf("github: reading private key from %s: %w", cfg.PrivateKeyPath, err)
		}
		privateKey = string(data)
	}

	client, err := NewClient(Config{
		AppID:      cfg.AppID,
		PrivateKey: privateKey,
		BaseURL:    cfg.BaseURL,
	})
	if err != nil {
		return fmt.Errorf("github: creating client: %w", err)
	}
	e.client = client

	// Branch safety defaults.
	branchPrefix := cfg.BranchPrefix
	if branchPrefix == "" {
		branchPrefix = "agent/"
	}

	protectedRefs := []string{"main", "master", "release/*"}
	if cfg.ProtectedRefs != "" {
		protectedRefs = strings.Split(cfg.ProtectedRefs, ",")
	}

	e.config = GitHubToolConfig{
		BranchPrefix:  branchPrefix,
		ProtectedRefs: protectedRefs,
	}

	// Register tools.
	if err := registerTools(ctx.Registry, e.client, e.config); err != nil {
		return fmt.Errorf("github: registering tools: %w", err)
	}

	e.logger.Info("github extension initialized",
		"app_id", cfg.AppID,
		"base_url", client.baseURL,
		"branch_prefix", branchPrefix,
	)

	return nil
}

// Start blocks until context is cancelled. No background process needed for tools-only extension.
func (e *Extension) Start(ctx context.Context) error {
	e.logger.Info("github extension started (tools only, no background process)")
	<-ctx.Done()
	return nil
}

// Stop is a no-op for this tools-only extension.
func (e *Extension) Stop(ctx context.Context) error {
	e.logger.Info("github extension stopped")
	return nil
}

// Verify Extension implements the interface at compile time.
var _ extension.Extension = (*Extension)(nil)
var _ tools.Tool = (*pushToBranchTool)(nil)
