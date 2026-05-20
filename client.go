package github

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	defaultBaseURL    = "https://api.github.com"
	tokenRefreshAhead = 5 * time.Minute
)

// InstallationToken represents a GitHub App installation access token.
type InstallationToken struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// TokenResponse is the API response for creating an installation token.
type TokenResponse struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
}

// InstallationsResponse is the API response for listing installations.
type InstallationsResponse struct {
	Installations []struct {
		ID      int64 `json:"id"`
		Account struct {
			Login string `json:"login"`
		} `json:"account"`
	} `json:"installations"`
}

// Config holds the configuration for the GitHub App client.
type Config struct {
	AppID      int64
	PrivateKey string // PEM-encoded RSA private key
	BaseURL    string // defaults to https://api.github.com
}

// Client is a GitHub App client that authenticates as an installation.
type Client struct {
	appID      int64
	privateKey *rsa.PrivateKey
	baseURL    string
	httpClient *http.Client

	mu            sync.Mutex
	installations map[int64]*InstallationToken // installationID → token
}

// NewClient creates a new GitHub App client from the given config.
func NewClient(cfg Config) (*Client, error) {
	if cfg.AppID == 0 {
		return nil, fmt.Errorf("github: app_id is required")
	}

	key, err := parsePrivateKey(cfg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("github: parsing private key: %w", err)
	}

	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	baseURL = strings.TrimRight(baseURL, "/")

	return &Client{
		appID:         cfg.AppID,
		privateKey:    key,
		baseURL:       baseURL,
		httpClient:    &http.Client{Timeout: 30 * time.Second},
		installations: make(map[int64]*InstallationToken),
	}, nil
}

// --- Authentication ---

// generateJWT creates a signed JSON Web Token for the GitHub App.
func (c *Client) generateJWT() (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"iat": now.Unix(),
		"exp": now.Add(10 * time.Minute).Unix(),
		"iss": c.appID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(c.privateKey)
}

// getInstallationToken returns a valid installation access token, refreshing if necessary.
func (c *Client) getInstallationToken(ctx context.Context, installationID int64) (string, error) {
	c.mu.Lock()
	tok, exists := c.installations[installationID]
	c.mu.Unlock()

	if exists && time.Now().Add(tokenRefreshAhead).Before(tok.ExpiresAt) {
		return tok.Token, nil
	}

	jwtStr, err := c.generateJWT()
	if err != nil {
		return "", fmt.Errorf("generating JWT: %w", err)
	}

	url := fmt.Sprintf("%s/app/installations/%d/access_tokens", c.baseURL, installationID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return "", fmt.Errorf("creating token request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+jwtStr)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("requesting installation token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("GitHub returned %d creating installation token: %s", resp.StatusCode, string(body))
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("decoding token response: %w", err)
	}

	expiresAt, err := time.Parse(time.RFC3339, tokenResp.ExpiresAt)
	if err != nil {
		return "", fmt.Errorf("parsing token expiry: %w", err)
	}

	newTok := &InstallationToken{
		Token:     tokenResp.Token,
		ExpiresAt: expiresAt,
	}

	c.mu.Lock()
	c.installations[installationID] = newTok
	c.mu.Unlock()

	return newTok.Token, nil
}

// --- Installation Discovery ---

// GetInstallationForRepo finds the installation ID for a specific repository.
func (c *Client) GetInstallationForRepo(ctx context.Context, owner, repo string) (int64, error) {
	jwtStr, err := c.generateJWT()
	if err != nil {
		return 0, fmt.Errorf("generating JWT: %w", err)
	}

	url := fmt.Sprintf("%s/repos/%s/%s/installation", c.baseURL, owner, repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+jwtStr)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("fetching installation: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("GitHub returned %d looking up installation for %s/%s: %s", resp.StatusCode, owner, repo, string(body))
	}

	var result struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, fmt.Errorf("decoding installation: %w", err)
	}

	return result.ID, nil
}

// --- Authenticated API Methods ---

// doAuthenticated performs an API request as the app installation.
func (c *Client) doAuthenticated(ctx context.Context, installationID int64, method, path string, body io.Reader) (*http.Response, error) {
	token, err := c.getInstallationToken(ctx, installationID)
	if err != nil {
		return nil, fmt.Errorf("getting installation token: %w", err)
	}

	url := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	return c.httpClient.Do(req)
}

// --- Git Data API ---

// GetBranchSHA returns the SHA of the latest commit on a branch.
func (c *Client) GetBranchSHA(ctx context.Context, installationID int64, owner, repo, branch string) (string, error) {
	path := fmt.Sprintf("/repos/%s/%s/git/refs/heads/%s", owner, repo, branch)
	resp, err := c.doAuthenticated(ctx, installationID, http.MethodGet, path, nil)
	if err != nil {
		return "", fmt.Errorf("getting branch ref: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("GitHub returned %d getting branch SHA: %s", resp.StatusCode, string(body))
	}

	var refData struct {
		Object struct {
			SHA string `json:"sha"`
		} `json:"object"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&refData); err != nil {
		return "", fmt.Errorf("decoding ref: %w", err)
	}

	return refData.Object.SHA, nil
}

// CreateRef creates a new branch ref pointing at the given SHA.
func (c *Client) CreateRef(ctx context.Context, installationID int64, owner, repo, ref, sha string) error {
	body := fmt.Sprintf(`{"ref":"refs/heads/%s","sha":"%s"}`, ref, sha)
	resp, err := c.doAuthenticated(ctx, installationID, http.MethodPost,
		fmt.Sprintf("/repos/%s/%s/git/refs", owner, repo),
		strings.NewReader(body))
	if err != nil {
		return fmt.Errorf("creating ref: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("GitHub returned %d creating ref: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

// CreateCommit creates a commit on a branch using the Git Data API.
func (c *Client) CreateCommit(ctx context.Context, installationID int64, owner, repo, branch, message string, files map[string]string) (string, error) {
	// Step 1: Get the current branch tip.
	refPath := fmt.Sprintf("/repos/%s/%s/git/refs/heads/%s", owner, repo, branch)
	resp, err := c.doAuthenticated(ctx, installationID, http.MethodGet, refPath, nil)
	if err != nil {
		return "", fmt.Errorf("getting branch ref: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("GitHub returned %d getting branch ref: %s", resp.StatusCode, string(respBody))
	}

	var refData struct {
		Object struct {
			SHA string `json:"sha"`
		} `json:"object"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&refData); err != nil {
		return "", fmt.Errorf("decoding ref: %w", err)
	}
	parentSHA := refData.Object.SHA

	// Step 2: Get the current commit to find its tree.
	commitPath := fmt.Sprintf("/repos/%s/%s/git/commits/%s", owner, repo, parentSHA)
	resp, err = c.doAuthenticated(ctx, installationID, http.MethodGet, commitPath, nil)
	if err != nil {
		return "", fmt.Errorf("getting parent commit: %w", err)
	}
	defer resp.Body.Close()

	var commitData struct {
		Tree struct {
			SHA string `json:"sha"`
		} `json:"tree"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&commitData); err != nil {
		return "", fmt.Errorf("decoding commit: %w", err)
	}

	// Step 3: Create blobs for each file and build tree entries.
	var treeEntries []map[string]interface{}
	for path, content := range files {
		blobBody := fmt.Sprintf(`{"content":%s,"encoding":"utf-8"}`, jsonString(content))
		resp, err := c.doAuthenticated(ctx, installationID, http.MethodPost,
			fmt.Sprintf("/repos/%s/%s/git/blobs", owner, repo),
			strings.NewReader(blobBody))
		if err != nil {
			return "", fmt.Errorf("creating blob for %s: %w", path, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusCreated {
			respBody, _ := io.ReadAll(resp.Body)
			return "", fmt.Errorf("GitHub returned %d creating blob: %s", resp.StatusCode, string(respBody))
		}

		var blobResult struct {
			SHA string `json:"sha"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&blobResult); err != nil {
			return "", fmt.Errorf("decoding blob: %w", err)
		}

		treeEntries = append(treeEntries, map[string]interface{}{
			"path": path,
			"mode": "100644",
			"type": "blob",
			"sha":  blobResult.SHA,
		})
	}

	// Step 4: Create a new tree.
	treeReq := map[string]interface{}{
		"base_tree": commitData.Tree.SHA,
		"tree":      treeEntries,
	}
	treeBody, err := json.Marshal(treeReq)
	if err != nil {
		return "", fmt.Errorf("marshaling tree request: %w", err)
	}

	resp, err = c.doAuthenticated(ctx, installationID, http.MethodPost,
		fmt.Sprintf("/repos/%s/%s/git/trees", owner, repo),
		strings.NewReader(string(treeBody)))
	if err != nil {
		return "", fmt.Errorf("creating tree: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("GitHub returned %d creating tree: %s", resp.StatusCode, string(respBody))
	}

	var treeResult struct {
		SHA string `json:"sha"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&treeResult); err != nil {
		return "", fmt.Errorf("decoding tree: %w", err)
	}

	// Step 5: Create the commit.
	commitReq := map[string]interface{}{
		"message": message,
		"tree":    treeResult.SHA,
		"parents": []string{parentSHA},
	}
	commitBody, err := json.Marshal(commitReq)
	if err != nil {
		return "", fmt.Errorf("marshaling commit request: %w", err)
	}

	resp, err = c.doAuthenticated(ctx, installationID, http.MethodPost,
		fmt.Sprintf("/repos/%s/%s/git/commits", owner, repo),
		strings.NewReader(string(commitBody)))
	if err != nil {
		return "", fmt.Errorf("creating commit: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("GitHub returned %d creating commit: %s", resp.StatusCode, string(respBody))
	}

	var commitResult struct {
		SHA string `json:"sha"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&commitResult); err != nil {
		return "", fmt.Errorf("decoding commit: %w", err)
	}

	// Step 6: Update the branch ref to point to the new commit.
	if err := c.updateRef(ctx, installationID, owner, repo, branch, commitResult.SHA); err != nil {
		return "", fmt.Errorf("updating branch ref: %w", err)
	}

	return commitResult.SHA, nil
}

// updateRef updates an existing branch ref to point at a new SHA.
func (c *Client) updateRef(ctx context.Context, installationID int64, owner, repo, ref, sha string) error {
	path := fmt.Sprintf("/repos/%s/%s/git/refs/heads/%s", owner, repo, ref)
	body := fmt.Sprintf(`{"sha":"%s","force":false}`, sha)
	resp, err := c.doAuthenticated(ctx, installationID, http.MethodPatch, path, strings.NewReader(body))
	if err != nil {
		return fmt.Errorf("updating ref: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("GitHub returned %d updating ref: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

// --- Pull Request API ---

// CreatePullRequest creates a new pull request.
func (c *Client) CreatePullRequest(ctx context.Context, installationID int64, owner, repo string, opts CreatePROptions) (*PullRequest, error) {
	body, err := json.Marshal(opts)
	if err != nil {
		return nil, fmt.Errorf("marshaling PR request: %w", err)
	}

	path := fmt.Sprintf("/repos/%s/%s/pulls", owner, repo)
	resp, err := c.doAuthenticated(ctx, installationID, http.MethodPost, path, strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("creating PR: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitHub returned %d creating PR: %s", resp.StatusCode, string(respBody))
	}

	var pr PullRequest
	if err := json.NewDecoder(resp.Body).Decode(&pr); err != nil {
		return nil, fmt.Errorf("decoding PR: %w", err)
	}

	return &pr, nil
}

// UpdatePullRequest updates an existing pull request (title, body).
func (c *Client) UpdatePullRequest(ctx context.Context, installationID int64, owner, repo string, number int, title, body string) (*PullRequest, error) {
	updates := map[string]string{}
	if title != "" {
		updates["title"] = title
	}
	if body != "" {
		updates["body"] = body
	}

	reqBody, err := json.Marshal(updates)
	if err != nil {
		return nil, fmt.Errorf("marshaling update: %w", err)
	}

	path := fmt.Sprintf("/repos/%s/%s/pulls/%d", owner, repo, number)
	resp, err := c.doAuthenticated(ctx, installationID, http.MethodPatch, path, strings.NewReader(string(reqBody)))
	if err != nil {
		return nil, fmt.Errorf("updating PR: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitHub returned %d updating PR: %s", resp.StatusCode, string(respBody))
	}

	var pr PullRequest
	if err := json.NewDecoder(resp.Body).Decode(&pr); err != nil {
		return nil, fmt.Errorf("decoding PR: %w", err)
	}

	return &pr, nil
}

// GetPullRequest gets a single PR by number.
func (c *Client) GetPullRequest(ctx context.Context, installationID int64, owner, repo string, number int) (*PullRequest, error) {
	path := fmt.Sprintf("/repos/%s/%s/pulls/%d", owner, repo, number)

	resp, err := c.doAuthenticated(ctx, installationID, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("getting PR: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitHub returned %d getting PR: %s", resp.StatusCode, string(body))
	}

	var pr PullRequest
	if err := json.NewDecoder(resp.Body).Decode(&pr); err != nil {
		return nil, fmt.Errorf("decoding PR: %w", err)
	}

	return &pr, nil
}

// ListPullRequests lists PRs for a repo, optionally filtered.
func (c *Client) ListPullRequests(ctx context.Context, installationID int64, owner, repo, state, head string) (PullRequestListResponse, error) {
	path := fmt.Sprintf("/repos/%s/%s/pulls?per_page=50", owner, repo)
	if state != "" {
		path += "&state=" + state
	}
	if head != "" {
		path += "&head=" + head
	}

	resp, err := c.doAuthenticated(ctx, installationID, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("listing PRs: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitHub returned %d listing PRs: %s", resp.StatusCode, string(body))
	}

	var prs PullRequestListResponse
	if err := json.NewDecoder(resp.Body).Decode(&prs); err != nil {
		return nil, fmt.Errorf("decoding PRs: %w", err)
	}

	return prs, nil
}

// --- Comments API ---

// CommentOnPullRequest adds a comment to a PR (uses the issues comments API).
func (c *Client) CommentOnPullRequest(ctx context.Context, installationID int64, owner, repo string, pullNumber int, body string) (*Comment, error) {
	reqBody := map[string]string{"body": body}
	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshaling comment: %w", err)
	}

	path := fmt.Sprintf("/repos/%s/%s/issues/%d/comments", owner, repo, pullNumber)
	resp, err := c.doAuthenticated(ctx, installationID, http.MethodPost, path, strings.NewReader(string(jsonBody)))
	if err != nil {
		return nil, fmt.Errorf("creating comment: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitHub returned %d creating comment: %s", resp.StatusCode, string(respBody))
	}

	var comment Comment
	if err := json.NewDecoder(resp.Body).Decode(&comment); err != nil {
		return nil, fmt.Errorf("decoding comment: %w", err)
	}

	return &comment, nil
}

// --- Helpers ---

// jsonString returns a JSON-escaped string (without quotes).
func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// parsePrivateKey parses a PEM-encoded RSA private key.
func parsePrivateKey(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		keyIfc, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("parsing as PKCS1 (%w) and PKCS8 (%w)", err, err2)
		}
		rsaKey, ok := keyIfc.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key is not RSA")
		}
		return rsaKey, nil
	}

	return key, nil
}
