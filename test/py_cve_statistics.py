import pandas as pd
import requests
from lib.cve_database import get_conn, ConnSearcher
from lib.commit import commit

def get_github_repo_stars(url):
    """
    Fetch the number of stars for a given GitHub repository.

    :param owner: The owner of the repository.
    :param repo: The repository name.
    :return: The number of stars or a message if the repo is not found.
    """
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        return data['stargazers_count']
    else:
        return "Repository not found or access denied."

DATA_PATH = "/Users/whilebug/Desktop/Projects/CVEfixes_repo/Data"
conn=get_conn(DATA_PATH=DATA_PATH)
conn_searcher = ConnSearcher(conn=conn)

PY_LANGUAGE = "Python"
cves = conn_searcher.get_cve_by_language(language=PY_LANGUAGE)
cves.to_csv("py_cves.csv")

repo_list = list(set(cves["repo_url"]))
#for repo_url in repo_list:
#    star_num = get_github_repo_stars(repo_url)
#    print(star_num)