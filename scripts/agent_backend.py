from flask import Flask, request, jsonify
import subprocess
import json

app = Flask(__name__)

@app.route('/run_swe', methods=['POST'])
def run_script():
    # 从请求中获取数据
    #print(request.json)
    request_dict = json.loads(request.json)
    #print(request_dict)
    model_name = request_dict['model_name']
    repo_path = request_dict['repo_path']
    data_path = request_dict['data_path']
    config_file = request_dict['config_file']

    # 构建命令行
    command = [
        "python", "run.py",
        "--model_name", model_name,
        "--repo_path", repo_path,
        "--data_path", data_path,
        "--config_file", config_file
    ]

    # 执行命令行
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # 实时读取输出流
        while True:
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                print(output.strip())  # 打印实时输出

        stderr = process.stderr.read()  # 读取所有错误输出
        if stderr:
            print("STDERR:", stderr.strip())

        return jsonify({"message": "Script executed successfully"}), 200
    except subprocess.CalledProcessError as e:
        print("Error:", e.stderr.strip())  # 打印错误信息到控制台
        return jsonify({"message": "Script execution failed", "error": e.stderr.strip()}), 400


if __name__ == '__main__':
    app.run(debug=True)
