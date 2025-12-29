"""GitHub data provider for Neo blockchain analysis"""

import os
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
        """Fetch issues data from GitHub"""
        query = gql("""
        query($owner: String!, $repo: String!, $start_date: DateTime!, $end_date: DateTime!) {
            repository(owner: $owner, name: $repo) {
                issues(first: 100, orderBy: {field: CREATED_AT, direction: DESC}, 
                       filterBy: {createdAt: {start: $start_date, end: $end_date}}) {
                    nodes {
                        id
                        title
                        body
                        state
                        createdAt
                        updatedAt
                        closedAt
                        author {
                            login
                        }
                        labels(first: 10) {
                            nodes {
                                name
                            }
                        }
                        comments {
                            totalCount
                        }
                    }
                }
            }
        }
        """)
        
        variables = {
            "owner": owner,
            "repo": repo,
            "start_date": start_date,
            "end_date": end_date
        }
        
        try:
            result = self.client.execute(query, variable_values=variables)
            return result.get("repository", {}).get("issues", {}).get("nodes", [])
        except Exception as e:
            raise Exception(f"Failed to fetch issues: {str(e)}")
    
    async def fetch_pull_requests(self, owner: str, repo: str, start_date: str, end_date: str) -> List[Dict[str, Any]]:
        """Fetch pull requests data from GitHub"""
        query = gql("""
        query($owner: String!, $repo: String!, $start_date: DateTime!, $end_date: DateTime!) {
            repository(owner: $owner, name: $repo) {
                pullRequests(first: 100, orderBy: {field: CREATED_AT, direction: DESC}, 
                           filterBy: {createdAt: {start: $start_date, end: $end_date}}) {
                    nodes {
                        id
                        title
                        body
                        state
                        createdAt
                        updatedAt
                        closedAt
                        mergedAt
                        author {
                            login
                        }
                        labels(first: 10) {
                            nodes {
                                name
                            }
                        }
                        comments {
                            totalCount
                        }
                        reviews {
                            totalCount
                        }
                        commits {
                            totalCount
                        }
                    }
                }
            }
        }
        """)
        
        variables = {
            "owner": owner,
            "repo": repo,
            "start_date": start_date,
            "end_date": end_date
        }
        
        try:
            result = self.client.execute(query, variable_values=variables)
            return result.get("repository", {}).get("pullRequests", {}).get("nodes", [])
        except Exception as e:
            raise Exception(f"Failed to fetch pull requests: {str(e)}")
    
    async def fetch_commits(self, owner: str, repo: str, start_date: str, end_date: str) -> List[Dict[str, Any]]:
        """Fetch commits data from GitHub"""
        query = gql("""
        query($owner: String!, $repo: String!, $start_date: DateTime!, $end_date: DateTime!) {
            repository(owner: $owner, name: $repo) {
                defaultBranchRef {
                    target {
                        ... on Commit {
                            history(since: $start_date, until: $end_date, first: 100) {
                                nodes {
                                    id
                                    message
                                    committedDate
                                    author {
                                        name
                                        email
                                    }
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
        
        variables = {
            "owner": owner,
            "repo": repo,
            "start_date": start_date,
            "end_date": end_date
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
                watcherCount
                openIssues: issues(states: OPEN) {
                    totalCount
                }
                openPullRequests: pullRequests(states: OPEN) {
                    totalCount
                }
                licenseInfo {
                    name
                }
                topics(first: 10) {
                    nodes {
                        topic {
                            name
                        }
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
            return result.get("repository", {})
        except Exception as e:
            raise Exception(f"Failed to fetch repository info: {str(e)}")
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if hasattr(self, 'client'):
            self.client.close() 