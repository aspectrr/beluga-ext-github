package github

// CreatePROptions are the options for creating a pull request.
type CreatePROptions struct {
	Title string `json:"title"`
	Body  string `json:"body"`
	Head  string `json:"head"`
	Base  string `json:"base"`
	Draft bool   `json:"draft"`
}

// PullRequest represents a GitHub pull request.
type PullRequest struct {
	Number  int      `json:"number"`
	Title   string   `json:"title"`
	Body    string   `json:"body"`
	State   string   `json:"state"`
	Head    PRBranch `json:"head"`
	Base    PRBranch `json:"base"`
	HTMLURL string   `json:"html_url"`
	Draft   bool     `json:"draft"`
	User    PRUser   `json:"user"`
}

// PRBranch represents a branch ref in a PR.
type PRBranch struct {
	Ref  string `json:"ref"`
	SHA  string `json:"sha"`
	Repo struct {
		FullName string `json:"full_name"`
	} `json:"repo"`
}

// PRUser represents a GitHub user.
type PRUser struct {
	Login string `json:"login"`
}

// PullRequestListResponse is the API response for listing PRs.
type PullRequestListResponse []PullRequest

// Comment represents an issue/PR comment.
type Comment struct {
	ID   int64  `json:"id"`
	Body string `json:"body"`
	User PRUser `json:"user"`
}
