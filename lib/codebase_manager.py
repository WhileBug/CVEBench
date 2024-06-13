import git
import requests
import json
import os
from lib.cve_folder import CVEFolder

class codebaseManager:
    def __init__(
            self,
            agent_backend_url='http://127.0.0.1:5000/run_swe'
    ):
        self.agent_backend_url=agent_backend_url

    def get_previous_commit(self, repo_url, commit_hash):
        # GitHub API URL preparation
        api_url = repo_url.replace("github.com", "api.github.com/repos")
        commit_url = f"{api_url}/commits/{commit_hash}"

        # Making a request to GitHub API to get the specific commit data
        response = requests.get(commit_url)
        data = response.json()

        # Extracting the parent commit SHA
        parent_commit_hash = data['parents'][0]['sha']
        return parent_commit_hash

    def clone_and_checkout_previous_commit(self, repo_url, commit_sha, repo_dir, parent_commit=None):
        if not os.path.exists(repo_dir):
            # Getting the previous commit
            if parent_commit is None:
                previous_commit_sha = self.get_previous_commit(repo_url, commit_sha)
            else:
                previous_commit_sha = parent_commit


            # Cloning the repo
            #repo_dir = repo_url.split('/')[-1]  # Assumes URL ends with repo name
            repo = git.Repo.clone_from(repo_url, repo_dir)


            # Checking out the previous commit
            repo.git.checkout(previous_commit_sha)
            print(f"Repository cloned and checked out to previous commit: {previous_commit_sha}")
        else:
            print("Already cloned")

    def unit_test_generate(
            self,
            cve_folder:CVEFolder,
            unit_test_prompt,
            home_path
    ):

        if os.path.exists(cve_folder.unit_test_path):
            pass
        else:
            os.mkdir(cve_folder.unit_test_path)
        with open(cve_folder.unit_test_issue_path, 'w+') as file:
            file.write(unit_test_prompt)

        # 定义发送到接口的数据
        data = {
            "model_name": "azure:gpt4",
            "repo_path": home_path+"/"+cve_folder.repo_path,
            "data_path": home_path+"/"+cve_folder.unit_test_issue_path,
            "config_file": "config/default_from_url.yaml"
        }
        # 将数据转换为 JSON 格式
        json_data = json.dumps(data)
        # 发送 POST 请求
        response = requests.post(self.agent_backend_url, json=json_data)
        # 打印响应内容
        print("Status Code:", response.status_code)
        print("Response Body:", response.json())