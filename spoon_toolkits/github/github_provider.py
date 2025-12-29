"""GitHub data provider for Neo blockchain analysis"""

import os
from datetime import datetime, timezone
from typing import Dict, Any, List
from gql import gql, Client
from gql.transport.requests import RequestsHTTPTransport

class GitHubProvider:
    """GitHub API data provider"""
    
    def __init__(self, token: str = None):
        self.token = token or os.getenv("GITHUB_TOKEN")
        if not self.token:
            raise ValueError("GitHub token is required. Set GITHUB_TOKEN environment variable or pass token parameter.")
        
        # Setup GraphQL client
        transport = RequestsHTTPTransport(
            url='https://api.github.com/graphql',
            headers={'Authorization': f'Bearer {self.token}'}
        )
        self.client = Client(transport=transport, fetch_schema_from_transport=True)
    
    async def fetch_issues(self, owner: str, repo: str, start_date: str, end_date: str) -> List[Dict[str, Any]]:
        """Fetch issues data from GitHub."""
        query = gql("""
        query($owner: String!, $repo: String!) {
            repository(owner: $owner, name: $repo) {
                issues(first: 100, orderBy: {field: CREATED_AT, direction: DESC}) {
                    nodes {
                        id
                        title
                        body
                        state
                        createdAt
                        updatedAt
                        closedAt
                        author { login }
                        labels(first: 10) { nodes { name } }
                        comments { totalCount }
                    }
                }
            }
        }
        """
        )
        
        variables = {
            "owner": owner,
            "repo": repo,
        }
        
        try:
            result = self.client.execute(query, variable_values=variables)
            issues = result.get("repository", {}).get("issues", {}).get("nodes", []) or []

            # Client-side filter by createdAt range
            start_dt = datetime.fromisoformat(start_date.replace("Z", "+00:00")).astimezone(timezone.utc)
            end_dt = datetime.fromisoformat(end_date.replace("Z", "+00:00")).astimezone(timezone.utc)

            filtered = []
            for issue in issues:
                created = issue.get("createdAt")
                if not created:
                    continue
                try:
                    created_dt = datetime.fromisoformat(created.replace("Z", "+00:00")).astimezone(timezone.utc)
                except Exception:
                    continue
                if start_dt <= created_dt <= end_dt:
                    filtered.append(issue)

            return filtered
        except Exception as e:
            raise Exception(f"Failed to fetch issues: {str(e)}")
    
    async def fetch_pull_requests(self, owner: str, repo: str, start_date: str, end_date: str) -> List[Dict[str, Any]]:
        """Fetch pull requests data from GitHub.

        Note: pullRequests filterBy does not support createdAt; fetch recent and filter client-side.
        """
        query = gql("""
        query($owner: String!, $repo: String!) {
            repository(owner: $owner, name: $repo) {
                pullRequests(first: 100, orderBy: {field: CREATED_AT, direction: DESC}) {
                    nodes {
                        id
                        title
                        body
                        state
                        createdAt
                        updatedAt
                        closedAt
                        mergedAt
                        author { login }
                        labels(first: 10) { nodes { name } }
                        comments { totalCount }
                        reviews { totalCount }
                        commits { totalCount }
                    }
                }
            }
        }
        """)
        
        variables = {
            "owner": owner,
            "repo": repo
        }
        
        try:
            result = self.client.execute(query, variable_values=variables)
            prs = result.get("repository", {}).get("pullRequests", {}).get("nodes", []) or []

            start_dt = datetime.fromisoformat(start_date.replace("Z", "+00:00")).astimezone(timezone.utc)
            end_dt = datetime.fromisoformat(end_date.replace("Z", "+00:00")).astimezone(timezone.utc)

            filtered = []
            for pr in prs:
                created = pr.get("createdAt")
                if not created:
                    continue
                try:
                    created_dt = datetime.fromisoformat(created.replace("Z", "+00:00")).astimezone(timezone.utc)
                except Exception:
                    continue
                if start_dt <= created_dt <= end_dt:
                    filtered.append(pr)

            return filtered
        except Exception as e:
            raise Exception(f"Failed to fetch pull requests: {str(e)}")
    
    async def fetch_commits(self, owner: str, repo: str, start_date: str, end_date: str) -> List[Dict[str, Any]]:
        """Fetch commits data from GitHub."""
        query = gql("""
        query($owner: String!, $repo: String!, $start_ts: GitTimestamp!, $end_ts: GitTimestamp!) {
            repository(owner: $owner, name: $repo) {
                defaultBranchRef {
                    target {
                        ... on Commit {
                            history(since: $start_ts, until: $end_ts, first: 100) {
                                nodes {
                                    id
                                    message
                                    committedDate
                                    author { name email }
                                    additions
                                    deletions
                                    changedFiles
                                }
                            }
                        }
                    }
                }
            }
        }
        """)
        
        def to_ts(date_str: str) -> str:
            if "T" in date_str:
                return date_str
            return f"{date_str}T00:00:00Z"
        
        variables = {
            "owner": owner,
            "repo": repo,
            "start_ts": to_ts(start_date),
            "end_ts": to_ts(end_date)
        }
        
        try:
            result = self.client.execute(query, variable_values=variables)
            history = result.get("repository", {}).get("defaultBranchRef", {}).get("target", {}).get("history", {})
            return history.get("nodes", [])
        except Exception as e:
            raise Exception(f"Failed to fetch commits: {str(e)}")
    
    async def fetch_repository_info(self, owner: str, repo: str) -> Dict[str, Any]:
        """Fetch repository information"""
        query = gql("""
        query($owner: String!, $repo: String!) {
            repository(owner: $owner, name: $repo) {
                id
                name
                description
                createdAt
                updatedAt
                primaryLanguage {
                    name
                }
                stargazerCount
                forkCount
                watchers {
                    totalCount
                }
                openIssues: issues(states: OPEN) {
                    totalCount
                }
                openPullRequests: pullRequests(states: OPEN) {
                    totalCount
                }
                licenseInfo {
                    name
                }
            }
        }
        """)
        
        variables = {
            "owner": owner,
            "repo": repo
        }
        
        try:
            result = self.client.execute(query, variable_values=variables)
            return result.get("repository", {})
        except Exception as e:
            raise Exception(f"Failed to fetch repository info: {str(e)}")
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if hasattr(self, 'client'):
            self.client.close() 