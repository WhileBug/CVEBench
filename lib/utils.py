from lib.cve_database import get_conn, ConnSearcher
from lib.codebase_manager import codebaseManager
from lib.prompt_generator import PromptGenerator
from lib.cve_folder import CVEFolder
import json
import requests
import git
from subprocess import Popen, PIPE
import os
import shutil
import ast

def collect_patch(
    collected_patch_path,
    issue_name,
    traj_dict
):
    patch_folder_path = traj_dict["path"] + traj_dict["prefix"] + issue_name + traj_dict["suffix"] + "/patches"
    all_patches = os.listdir(patch_folder_path)
    patch_files = [file for file in all_patches if file.endswith('.patch')]
    agent_patch_path = patch_folder_path + "/" + patch_files[0]
    shutil.copy(agent_patch_path, collected_patch_path)
    print(issue_name, "patch collected.")

def collect_traj(
    collected_traj_path,
    issue_name,
    traj_dict
):
    traj_folder_path = traj_dict["path"] + traj_dict["prefix"] + issue_name + traj_dict["suffix"]
    all_trajs = os.listdir(traj_folder_path)
    traj_files = [file for file in all_trajs if file.endswith('.traj')]
    agent_traj_path = traj_folder_path + "/" + traj_files[0]
    shutil.copy(agent_traj_path, collected_traj_path)
    print(issue_name, "traj collected.")

def copy_repo(repo_path, new_repo_path):
    if not os.path.exists(new_repo_path):
        shutil.copytree(repo_path, new_repo_path)

def apply_patch(repo_path, patch_path):
    # 初始化仓库对象
    repo = git.Repo(repo_path)
    # 确保工作目录是干净的
    if repo.is_dirty():
        raise Exception("仓库有未提交的更改，请先处理这些更改。")
    patch_path = os.path.abspath(patch_path)
    # 构建git apply命令
    #cmd = ['git', 'apply', patch_path]
    # 执行命令
    #process = Popen(cmd, stdout=PIPE, stderr=PIPE, cwd=repo_path)
    #stdout, stderr = process.communicate()
    try:
        repo.git.apply(patch_path)
    except Exception as e:
        print(e)
    # 检查命令是否执行成功
    #if process.returncode != 0:
    #    print(f"错误输出: {stderr.decode()}")
    #    raise Exception("Patch 应用失败")
    #print("Patch 已成功应用")
    return 0


def apply_patch_from_traj(
        repo_path,
        new_repo_path,
        traj_dict,
        issue_name
):
    copy_repo(repo_path, new_repo_path)
    patch_folder_path = traj_dict["path"]+traj_dict["prefix"]+issue_name+traj_dict["suffix"]+"/patches"
    all_patches = os.listdir(patch_folder_path)
    patch_files = [file for file in all_patches if file.endswith('.patch')]
    patch_path=patch_folder_path+"/"+patch_files[0]
    apply_patch(new_repo_path, patch_path)

def apply_patch_from_collections(
        repo_path,
        new_repo_path,
        collection_folder,
        issue_name
):
    copy_repo(repo_path, new_repo_path)
    apply_patch(new_repo_path, collection_folder+"/"+issue_name+".patch")


def call_agent(
    repo_path,
    data_path,
    agent_url='http://127.0.0.1:5000/run_swe'
):
    # 定义发送到接口的数据
    data = {
        "model_name": "azure:gpt4",
        "repo_path": repo_path,
        "data_path": data_path,
        "config_file": "config/default_from_url.yaml"
    }
    json_data = json.dumps(data)
    response = requests.post(agent_url, json=json_data)
    print("Status Code:", response.status_code)
    print("Response Body:", response.json())
    return response.json()

def fix_cve(
        cve_folder:CVEFolder,
        home_path:str,
        fix_level:int,
        prompt_generator:PromptGenerator,
        traj_dict:dict
):
    cve_folder.set_fix_name(fix_level=fix_level)

    if cve_folder.get_fix_status(fix_level=fix_level):
        print("Fix already generated")
    else:
        # 1. generate fix prompt and store it to an issue
        fix_prompt=prompt_generator.fix_issue_prompt_generate(
            cve_id=cve_folder.cve_id,
            fix_level=fix_level
        )
        with open(cve_folder.fix_issue_filename, 'w+') as file:
            file.write(fix_prompt)
        print("1. Fix issue generated")

        # 2. call agent to fix
        response=call_agent(
            repo_path=home_path+"/"+cve_folder.repo_path,
            data_path=home_path+"/"+cve_folder.fix_issue_filename
        )
        print("2. Fixed")

        collect_patch(
            collected_patch_path=cve_folder.fix_patch_filename,
            issue_name=cve_folder.fix_name,
            traj_dict=traj_dict
        )

        collect_traj(
            collected_traj_path=cve_folder.fix_traj_filename,
            issue_name=cve_folder.fix_name,
            traj_dict=traj_dict
        )

        # 3. apply patch
        '''
        apply_patch_from_traj(
            repo_path=home_path+"/"+cve_folder,
            new_repo_path=home_path+"/"+repo_dir+"-fix-"+str(fix_level),
            traj_dict=traj_dict,
            issue_name=issue_name
        )
        print("3. Patch applied")
        '''
        return response

def clone_repo(
        cve_id,
        conn_searcher:ConnSearcher,
        codebase_manager:codebaseManager,
        folder_path:str
):
    # 1. get CVE information
    cve_commit_info = conn_searcher.get_commit_info(cve_id=cve_id)
    cve_repo_url = cve_commit_info["repo_url"]
    cve_commit_hash = cve_commit_info["hash"]
    cve_commit_parents = ast.literal_eval(cve_commit_info["parents"])[0]
    print("1. CVE information get.")

    # 2. clone cve repo, and restore to father commit
    codebase_manager.clone_and_checkout_previous_commit(
        repo_url=cve_repo_url,
        commit_sha=cve_commit_hash,
        repo_dir=folder_path+"/" + cve_id,
        parent_commit=cve_commit_parents
    )
    print("2. Repo cloned.")
