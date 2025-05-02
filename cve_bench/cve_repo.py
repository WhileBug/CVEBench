import os
import requests
import git

class CVERepo:
    def __init__(
            self,
            cve_id:str,
            repo_url:str,
            commit_hash:str,
            repo_dir:str,
            old_path:str,
            code_before:str,
            code_after:str,
            parent_commit_hash:str=None
    ):
        self.cve_id = cve_id
        self.repo_url = repo_url
        self.commit_hash = commit_hash
        self.repo_url = repo_url
        self.repo_dir = repo_dir
        if parent_commit_hash is None:
            self.parent_commit_hash = self.get_previous_commit()
        else:
            self.parent_commit_hash = parent_commit_hash

        self.old_path = old_path
        self.code_before = code_before
        self.code_after = code_after

    def get_previous_commit(self):
        # GitHub API URL preparation
        api_url = self.repo_url.replace("github.com", "api.github.com/repos")
        commit_url = f"{api_url}/commits/{self.commit_hash}"

        # Making a request to GitHub API to get the specific commit data
        response = requests.get(commit_url)
        data = response.json()

        # Extracting the parent commit SHA
        parent_commit_hash = data['parents'][0]['sha']
        return parent_commit_hash

    def clone_and_checkout_previous_commit(self):
        if not os.path.exists(self.repo_dir):
            # Cloning the repo
            #repo_dir = repo_url.split('/')[-1]  # Assumes URL ends with repo name
            repo = git.Repo.clone_from(self.repo_url, self.repo_dir)
            # Checking out the previous commit
            repo.git.checkout(self.parent_commit_hash)
            print(f"Repository cloned and checked out to previous commit: {self.parent_commit_hash}")
        else:
            print("Already cloned")