// ── GitHub Extension ──────────────────────────────────────────
// Ported from Go (github.com/aspectrr/beluga-ext-github).
//
// GitHub App integration. Authenticates as installation to push code,
// create/update/list PRs, and comment on PRs. Branch safety enforced.

import { readFileSync } from "fs";
import type {
	Extension,
	ExtensionContext,
	Tool,
	ToolDef,
	ToolContext,
} from "@aspectrr/beluga-sdk";

// ── Config ─────────────────────────────────────────────────────

interface GitHubToolConfig {
	branchPrefix: string;
	protectedRefs: string[];
}

interface GitHubConfig {
	enabled: boolean;
	app_id: number;
	private_key?: string;
	private_key_path?: string;
	base_url?: string;
	branch_prefix?: string;
	protected_refs?: string;
}

// ── Types ──────────────────────────────────────────────────────

interface PullRequest {
	number: number;
	title: string;
	body?: string;
	state: string;
	head: { ref: string; sha: string; repo: { full_name: string } };
	base: { ref: string; sha: string; repo: { full_name: string } };
	html_url: string;
	draft: boolean;
	user: { login: string };
}

interface PRComment {
	id: number;
	body: string;
	user: { login: string };
}

interface CreatePROptions {
	title: string;
	body?: string;
	head: string;
	base: string;
	draft?: boolean;
}

// ── JWT + Crypto helpers ───────────────────────────────────────

function base64url(buf: Uint8Array | ArrayBuffer): string {
	const bytes = buf instanceof ArrayBuffer ? new Uint8Array(buf) : buf;
	return btoa(String.fromCharCode(...bytes))
		.replace(/\+/g, "-")
		.replace(/\//g, "_")
		.replace(/=+$/, "");
}

async function generateJWT(
	appId: number,
	privateKey: CryptoKey,
): Promise<string> {
	const now = Math.floor(Date.now() / 1000);
	const header = base64url(
		new TextEncoder().encode(JSON.stringify({ alg: "RS256", typ: "JWT" })),
	);
	const payload = base64url(
		new TextEncoder().encode(
			JSON.stringify({ iss: String(appId), iat: now - 60, exp: now + 600 }),
		),
	);
	const signInput = `${header}.${payload}`;
	const sig = await crypto.subtle.sign(
		"RSASSA-PKCS1-v1_5",
		privateKey,
		new TextEncoder().encode(signInput),
	);
	return `${signInput}.${base64url(sig)}`;
}

async function parsePEM(pem: string): Promise<CryptoKey> {
	const b64 = pem
		.replace(/-----BEGIN.*?-----/g, "")
		.replace(/-----END.*?-----/g, "")
		.replace(/\s/g, "");
	const der = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));

	try {
		return await crypto.subtle.importKey(
			"pkcs8",
			der,
			{ name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
			false,
			["sign"],
		);
	} catch {
		throw new Error(
			"Failed to import RSA key. Ensure the key is in PKCS#8 format (BEGIN PRIVATE KEY). " +
				"PKCS#1 format (BEGIN RSA PRIVATE KEY) is not supported by WebCrypto. " +
				"Convert with: openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in key.pem -out key_pkcs8.pem",
		);
	}
}

// ── GitHub API Client ──────────────────────────────────────────

class GitHubClient {
	private appId: number;
	private privateKey: CryptoKey;
	private baseUrl: string;
	private tokenCache = new Map<number, { token: string; expiresAt: number }>();
	private jwtCache: { jwt: string; expiresAt: number } | null = null;

	constructor(appId: number, privateKey: CryptoKey, baseUrl: string) {
		this.appId = appId;
		this.privateKey = privateKey;
		this.baseUrl = baseUrl;
	}

	private async getJWT(): Promise<string> {
		const now = Math.floor(Date.now() / 1000);
		if (this.jwtCache && this.jwtCache.expiresAt > now + 60)
			return this.jwtCache.jwt;
		const jwt = await generateJWT(this.appId, this.privateKey);
		this.jwtCache = { jwt, expiresAt: now + 540 };
		return jwt;
	}

	private async getInstallationToken(installationId: number): Promise<string> {
		const cached = this.tokenCache.get(installationId);
		if (cached && cached.expiresAt > Date.now() / 1000 + 300)
			return cached.token;

		const jwt = await this.getJWT();
		const resp = await fetch(
			`${this.baseUrl}/app/installations/${installationId}/access_tokens`,
			{
				method: "POST",
				headers: {
					Authorization: `Bearer ${jwt}`,
					Accept: "application/vnd.github+json",
					"X-GitHub-Api-Version": "2022-11-28",
				},
			},
		);
		if (!resp.ok)
			throw new Error(`Failed to get installation token: ${resp.status}`);

		const data = (await resp.json()) as { token: string; expires_at: string };
		const expiresAt = new Date(data.expires_at).getTime() / 1000;
		this.tokenCache.set(installationId, { token: data.token, expiresAt });
		return data.token;
	}

	async getInstallationForRepo(owner: string, repo: string): Promise<number> {
		const jwt = await this.getJWT();
		const resp = await fetch(
			`${this.baseUrl}/repos/${owner}/${repo}/installation`,
			{
				headers: {
					Authorization: `Bearer ${jwt}`,
					Accept: "application/vnd.github+json",
					"X-GitHub-Api-Version": "2022-11-28",
				},
			},
		);
		if (!resp.ok)
			throw new Error(
				`Installation not found for ${owner}/${repo}: ${resp.status}`,
			);
		const data = (await resp.json()) as { id: number };
		return data.id;
	}

	private async doAuthenticated<T>(
		method: string,
		path: string,
		installationId: number,
		body?: unknown,
	): Promise<T> {
		const token = await this.getInstallationToken(installationId);
		const headers: Record<string, string> = {
			Authorization: `Bearer ${token}`,
			Accept: "application/vnd.github+json",
			"X-GitHub-Api-Version": "2022-11-28",
		};
		const opts: RequestInit = { method, headers };
		if (body) {
			headers["Content-Type"] = "application/json";
			opts.body = JSON.stringify(body);
		}

		const resp = await fetch(`${this.baseUrl}${path}`, opts);
		if (!resp.ok) {
			const text = await resp.text();
			throw new Error(`GitHub API ${resp.status}: ${text}`);
		}
		if (resp.status === 204) return {} as T;
		return (await resp.json()) as T;
	}

	async getBranchSHA(
		owner: string,
		repo: string,
		branch: string,
		installId: number,
	): Promise<string> {
		const data = await this.doAuthenticated<{ object: { sha: string } }>(
			"GET",
			`/repos/${owner}/${repo}/git/refs/heads/${branch}`,
			installId,
		);
		return data.object.sha;
	}

	async createRef(
		owner: string,
		repo: string,
		ref: string,
		sha: string,
		installId: number,
	): Promise<void> {
		await this.doAuthenticated(
			"POST",
			`/repos/${owner}/${repo}/git/refs`,
			installId,
			{ ref, sha },
		);
	}

	async createCommit(
		owner: string,
		repo: string,
		branch: string,
		message: string,
		files: Array<{ path: string; content: string }>,
		installId: number,
	): Promise<string> {
		const parentSha = await this.getBranchSHA(owner, repo, branch, installId);
		const parentCommit = await this.doAuthenticated<{ tree: { sha: string } }>(
			"GET",
			`/repos/${owner}/${repo}/git/commits/${parentSha}`,
			installId,
		);
		const baseTreeSha = parentCommit.tree.sha;

		const blobs: Array<{
			path: string;
			sha: string;
			mode: string;
			type: string;
		}> = [];
		for (const file of files) {
			const blob = await this.doAuthenticated<{ sha: string }>(
				"POST",
				`/repos/${owner}/${repo}/git/blobs`,
				installId,
				{ content: file.content, encoding: "utf-8" },
			);
			blobs.push({ path: file.path, sha: blob.sha, mode: "100644", type: "blob" });
		}

		const tree = await this.doAuthenticated<{ sha: string }>(
			"POST",
			`/repos/${owner}/${repo}/git/trees`,
			installId,
			{ base_tree: baseTreeSha, tree: blobs },
		);

		const commit = await this.doAuthenticated<{ sha: string }>(
			"POST",
			`/repos/${owner}/${repo}/git/commits`,
			installId,
			{ message, tree: tree.sha, parents: [parentSha] },
		);

		await this.doAuthenticated(
			"PATCH",
			`/repos/${owner}/${repo}/git/refs/heads/${branch}`,
			installId,
			{ sha: commit.sha, force: false },
		);

		return commit.sha;
	}

	async createPullRequest(
		owner: string,
		repo: string,
		opts: CreatePROptions,
		installId: number,
	): Promise<PullRequest> {
		return this.doAuthenticated("POST", `/repos/${owner}/${repo}/pulls`, installId, opts);
	}

	async updatePullRequest(
		owner: string,
		repo: string,
		number: number,
		updates: Partial<CreatePROptions>,
		installId: number,
	): Promise<PullRequest> {
		return this.doAuthenticated("PATCH", `/repos/${owner}/${repo}/pulls/${number}`, installId, updates);
	}

	async getPullRequest(
		owner: string,
		repo: string,
		number: number,
		installId: number,
	): Promise<PullRequest> {
		return this.doAuthenticated("GET", `/repos/${owner}/${repo}/pulls/${number}`, installId);
	}

	async listPullRequests(
		owner: string,
		repo: string,
		state = "open",
		installId: number,
	): Promise<PullRequest[]> {
		return this.doAuthenticated(
			"GET",
			`/repos/${owner}/${repo}/pulls?state=${state}&per_page=50`,
			installId,
		);
	}

	async commentOnPullRequest(
		owner: string,
		repo: string,
		number: number,
		body: string,
		installId: number,
	): Promise<PRComment> {
		return this.doAuthenticated(
			"POST",
			`/repos/${owner}/${repo}/issues/${number}/comments`,
			installId,
			{ body },
		);
	}
}

// ── Branch validation ──────────────────────────────────────────

function matchesGlob(pattern: string, ref: string): boolean {
	if (pattern === ref) return true;
	if (pattern.endsWith("/*")) {
		const prefix = pattern.slice(0, -2);
		return ref.startsWith(prefix + "/") || ref === prefix;
	}
	return false;
}

function validateAgentBranch(branch: string, toolCfg: GitHubToolConfig): void {
	for (const pattern of toolCfg.protectedRefs) {
		if (matchesGlob(pattern, branch)) {
			throw new Error(`branch "${branch}" is protected (${pattern})`);
		}
	}
	if (!branch.startsWith(toolCfg.branchPrefix)) {
		throw new Error(`branch "${branch}" must start with "${toolCfg.branchPrefix}"`);
	}
}

function dryRun(): boolean {
	return process.env.BELUGA_DRY_RUN === "true";
}

// ── Tools ──────────────────────────────────────────────────────

class PushToBranchTool implements Tool {
	private client: GitHubClient;
	private toolCfg: GitHubToolConfig;

	constructor(client: GitHubClient, toolCfg: GitHubToolConfig) {
		this.client = client;
		this.toolCfg = toolCfg;
	}

	definition(): ToolDef {
		return {
			name: "github_push_to_branch",
			description:
				"Commit and push file changes to a branch. Branch must start with agent prefix. Protected branches never allowed. Creates branch from base if doesn't exist.",
			parameters: {
				type: "object",
				properties: {
					owner: { type: "string", description: "Repo owner" },
					repo: { type: "string", description: "Repo name" },
					branch: { type: "string", description: "Target branch (must start with agent/)" },
					base_branch: { type: "string", description: "Create-from branch (default: main)" },
					message: { type: "string", description: "Commit message" },
					files: {
						type: "array",
						items: {
							type: "object",
							properties: { path: { type: "string" }, content: { type: "string" } },
							required: ["path", "content"],
						},
						description: "Files to create/update",
					},
				},
				required: ["owner", "repo", "branch", "message", "files"],
			},
		};
	}

	async execute(args: Record<string, unknown>, _ctx: ToolContext): Promise<Record<string, unknown>> {
		if (dryRun()) return { status: "dry_run" };

		const { owner, repo, branch, message, files } = args as {
			owner: string; repo: string; branch: string; message: string;
			files: Array<{ path: string; content: string }>;
		};
		const baseBranch = (args.base_branch as string) || "main";

		if (!owner || !repo || !branch || !message || !files?.length) {
			throw new Error("owner, repo, branch, message, and files are required");
		}

		validateAgentBranch(branch, this.toolCfg);

		const installId = await this.client.getInstallationForRepo(owner, repo);

		// Ensure branch exists
		try {
			await this.client.getBranchSHA(owner, repo, branch, installId);
		} catch {
			const baseSha = await this.client.getBranchSHA(owner, repo, baseBranch, installId);
			await this.client.createRef(owner, repo, `refs/heads/${branch}`, baseSha, installId);
		}

		const commitSha = await this.client.createCommit(owner, repo, branch, message, files, installId);

		return {
			status: "pushed",
			owner, repo, branch, commit_sha: commitSha,
			files: files.map((f) => f.path),
			message,
		};
	}
}

class CreatePRTool implements Tool {
	private client: GitHubClient;
	private toolCfg: GitHubToolConfig;

	constructor(client: GitHubClient, toolCfg: GitHubToolConfig) {
		this.client = client;
		this.toolCfg = toolCfg;
	}

	definition(): ToolDef {
		return {
			name: "github_create_pull_request",
			description: "Open a PR. Head branch must be agent branch. PRs must be reviewed by human.",
			parameters: {
				type: "object",
				properties: {
					owner: { type: "string", description: "Repo owner" },
					repo: { type: "string", description: "Repo name" },
					title: { type: "string", description: "PR title" },
					body: { type: "string", description: "PR body (markdown)" },
					head: { type: "string", description: "Source branch (agent prefix enforced)" },
					base: { type: "string", description: "Target branch" },
					draft: { type: "boolean", description: "Create as draft" },
				},
				required: ["owner", "repo", "title", "head", "base"],
			},
		};
	}

	async execute(args: Record<string, unknown>, _ctx: ToolContext): Promise<Record<string, unknown>> {
		if (dryRun()) return { status: "dry_run" };

		const { owner, repo, title, head, base } = args as {
			owner: string; repo: string; title: string; head: string; base: string;
		};
		const body = args.body as string | undefined;
		const draft = args.draft as boolean | undefined;

		if (!owner || !repo || !title || !head || !base) {
			throw new Error("owner, repo, title, head, and base are required");
		}

		validateAgentBranch(head, this.toolCfg);
		if (base.startsWith(this.toolCfg.branchPrefix)) {
			throw new Error("base branch cannot be an agent branch");
		}

		const installId = await this.client.getInstallationForRepo(owner, repo);
		const pr = await this.client.createPullRequest(owner, repo, { title, body, head, base, draft }, installId);

		return {
			status: "created",
			pr_number: pr.number, pr_url: pr.html_url,
			pr_title: pr.title, pr_state: pr.state,
			draft: pr.draft, head_branch: pr.head.ref, base_branch: pr.base.ref,
			message: "PR created. Must be reviewed before merging.",
		};
	}
}

class CommentOnPRTool implements Tool {
	private client: GitHubClient;

	constructor(client: GitHubClient) {
		this.client = client;
	}

	definition(): ToolDef {
		return {
			name: "github_comment_on_pull_request",
			description: "Add a comment to a PR. Uses issues comments API.",
			parameters: {
				type: "object",
				properties: {
					owner: { type: "string", description: "Repo owner" },
					repo: { type: "string", description: "Repo name" },
					pull_number: { type: "integer", description: "PR number" },
					body: { type: "string", description: "Comment text (markdown)" },
				},
				required: ["owner", "repo", "pull_number", "body"],
			},
		};
	}

	async execute(args: Record<string, unknown>, _ctx: ToolContext): Promise<Record<string, unknown>> {
		if (dryRun()) return { status: "dry_run" };

		const { owner, repo, pull_number, body } = args as {
			owner: string; repo: string; pull_number: number; body: string;
		};
		if (!owner || !repo || !pull_number || !body) throw new Error("all fields required");

		const installId = await this.client.getInstallationForRepo(owner, repo);
		const comment = await this.client.commentOnPullRequest(owner, repo, pull_number, body, installId);

		return { status: "commented", comment_id: comment.id, pr_number: pull_number };
	}
}

class UpdatePRTool implements Tool {
	private client: GitHubClient;
	private toolCfg: GitHubToolConfig;

	constructor(client: GitHubClient, toolCfg: GitHubToolConfig) {
		this.client = client;
		this.toolCfg = toolCfg;
	}

	definition(): ToolDef {
		return {
			name: "github_update_pull_request",
			description: "Update PR title or description. Only PRs from agent branches can be updated.",
			parameters: {
				type: "object",
				properties: {
					owner: { type: "string", description: "Repo owner" },
					repo: { type: "string", description: "Repo name" },
					pull_number: { type: "integer", description: "PR number" },
					title: { type: "string", description: "New title" },
					body: { type: "string", description: "New body" },
				},
				required: ["owner", "repo", "pull_number"],
			},
		};
	}

	async execute(args: Record<string, unknown>, _ctx: ToolContext): Promise<Record<string, unknown>> {
		if (dryRun()) return { status: "dry_run" };

		const { owner, repo, pull_number } = args as {
			owner: string; repo: string; pull_number: number;
		};
		const title = args.title as string | undefined;
		const body = args.body as string | undefined;

		if (!title && !body) throw new Error("at least one of title or body required");

		const installId = await this.client.getInstallationForRepo(owner, repo);
		const pr = await this.client.getPullRequest(owner, repo, pull_number, installId);

		if (!pr.head.ref.startsWith(this.toolCfg.branchPrefix)) {
			throw new Error("only PRs from agent branches can be updated");
		}

		const updated = await this.client.updatePullRequest(owner, repo, pull_number, { title, body }, installId);

		return { status: "updated", pr_number: updated.number, pr_title: updated.title, pr_url: updated.html_url };
	}
}

class ListPRsTool implements Tool {
	private client: GitHubClient;

	constructor(client: GitHubClient) {
		this.client = client;
	}

	definition(): ToolDef {
		return {
			name: "github_list_pull_requests",
			description: "List PRs for a repo. Returns summary with number, title, state, branches, URL.",
			parameters: {
				type: "object",
				properties: {
					owner: { type: "string", description: "Repo owner" },
					repo: { type: "string", description: "Repo name" },
					state: { type: "string", description: "open, closed, or all", enum: ["open", "closed", "all"] },
				},
				required: ["owner", "repo"],
			},
		};
	}

	async execute(args: Record<string, unknown>, _ctx: ToolContext): Promise<Record<string, unknown>> {
		if (dryRun()) return { count: 0, pr_list: [] };

		const { owner, repo } = args as { owner: string; repo: string };
		const state = (args.state as string) || "open";

		const installId = await this.client.getInstallationForRepo(owner, repo);
		const prs = await this.client.listPullRequests(owner, repo, state, installId);

		const prList = prs.map((pr) => ({
			number: pr.number, title: pr.title, state: pr.state,
			head_branch: pr.head.ref, base_branch: pr.base.ref,
			html_url: pr.html_url, draft: pr.draft, author: pr.user?.login,
		}));

		return { count: prList.length, pr_list: prList };
	}
}

// ── Extension ──────────────────────────────────────────────────

class GitHubExtension implements Extension {
	name = "github";
	private client!: GitHubClient;

	async init(ctx: ExtensionContext): Promise<void> {
		const cfg = ctx.config as unknown as GitHubConfig;
		if (!cfg.app_id) throw new Error("github: app_id is required");

		let pem: string;
		if (cfg.private_key) {
			pem = cfg.private_key;
		} else if (cfg.private_key_path) {
			pem = readFileSync(cfg.private_key_path, "utf-8");
		} else {
			throw new Error("github: private_key or private_key_path is required");
		}

		const privateKey = await parsePEM(pem);
		const baseUrl = cfg.base_url || "https://api.github.com";
		this.client = new GitHubClient(cfg.app_id, privateKey, baseUrl);

		const toolCfg: GitHubToolConfig = {
			branchPrefix: cfg.branch_prefix || "agent/",
			protectedRefs: (cfg.protected_refs || "main,master,release/*")
				.split(",")
				.map((s) => s.trim()),
		};

		ctx.registry.register(new PushToBranchTool(this.client, toolCfg));
		ctx.registry.register(new CreatePRTool(this.client, toolCfg));
		ctx.registry.register(new CommentOnPRTool(this.client));
		ctx.registry.register(new UpdatePRTool(this.client, toolCfg));
		ctx.registry.register(new ListPRsTool(this.client));

		ctx.logger.info(
			{ app_id: cfg.app_id, base_url: baseUrl, branch_prefix: toolCfg.branchPrefix },
			"github extension initialized",
		);
	}

	async start(_signal: AbortSignal): Promise<void> {
		// Tools only — no background work
	}

	async stop(): Promise<void> {
		// No-op
	}
}

export default new GitHubExtension();
