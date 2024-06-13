from lib.utils import copy_repo
import shutil
import docker
from docker.errors import BuildError, ContainerError

def validate_repo_build(
        repo_path,
        fix_repo_path,
        unit_test_repo_path,
        script_filename="ACI_unit_test.py",
        shell_filename="ACI_unit_test.sh"
):
    val_repo_path = repo_path+"-validate"
    copy_repo(
        repo_path=fix_repo_path,
        new_repo_path=val_repo_path
    )

    script_path = unit_test_repo_path+"/"+script_filename
    shell_path = unit_test_repo_path+"/"+shell_filename
    val_script_path = val_repo_path+"/"+script_filename
    val_shell_path = val_repo_path + "/" + shell_filename

    shutil.copy(script_path, val_script_path)
    shutil.copy(shell_path, val_shell_path)

def validate_docker_build(
    python_version,
    repo_name
):
    with open('scripts/UnitTestDockerfile', 'r') as file:
        data = file.read()

    formatted_data = data.format(python_version=python_version, repo_name=repo_name)

    with open('test_repos/'+repo_name+"-Dockerfile", 'w+') as file:
        file.write(formatted_data)

def validate_in_docker(dockerfile_path, dockerfile, docker_tag):
    client = docker.from_env()
    # 定义你的Dockerfile和context的路径
    docker_tag = docker_tag.lower()#.replace("-", "_")

    try:
        # 构建 Docker 镜像
        print("Building Docker image...")
        image, build_logs = client.images.build(path=dockerfile_path, dockerfile=dockerfile, tag=docker_tag)

        # 运行容器并获取输出
        print("Running tests in Docker container...")
        container = client.containers.run(docker_tag, detach=True)
        output = container.logs(follow=True)
        print(output.decode('utf-8'))

        # 等待容器执行结束并获取退出代码
        exit_status = container.wait()
        print(f"Exit status: {exit_status['StatusCode']}")

        return output

    except BuildError as e:
        print(f"Build failed: {e}")
    except ContainerError as e:
        print(f"Container run failed: {e}")
    finally:
        # Cleanup
        client.containers.prune()
        client.images.prune()


def validate_fix(
        cve_id,
        repo_path,
        fix_repo_path,
        unit_test_repo_path,
        python_version="2.7"
):
    validate_repo_build(
        repo_path=repo_path,
        fix_repo_path=fix_repo_path,
        unit_test_repo_path=unit_test_repo_path
    )

    validate_docker_build(
        python_version=python_version,
        repo_name=cve_id + "-validate"
    )

    validate_in_docker(
        dockerfile_path="test_repos/",
        dockerfile=cve_id + "-validate-Dockerfile",
        docker_tag=cve_id + "-validate"
    )