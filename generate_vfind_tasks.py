import json
import subprocess
from pathlib import Path

import pandas as pd


RESULT_FILE = Path("result.xlsx")
DATA_FILE = Path("DATA.xlsx")
TARGET_REPO_ROOT = Path("target_repo")
WORKFLOW_OUTPUT_DIR = Path("workflow_output")
TMP_DIR = WORKFLOW_OUTPUT_DIR / "tmp"
RECON_DIR = WORKFLOW_OUTPUT_DIR / "recon"
VFIND_DIR = WORKFLOW_OUTPUT_DIR / "vfind"
CVELIST_DIR = WORKFLOW_OUTPUT_DIR / "cvelist"
TMP_JSON_FILE = TMP_DIR / "tmp.json"

RESULT_CVE_COL = "CVE"
DATA_CVE_COL = "CVE编号"
REQUIRED_DATA_COLUMNS = [
    "软件名",
    "CVE编号",
    "描述",
    "githuburl",
    "commit",
    "new_good",
    "cwe编号",
    "cwe链接",
]
RESULT_PROJECT_COL = "Project"


def normalize_cve(value):
    if pd.isna(value):
        return ""
    return str(value).strip()


def split_cve_values(value):
    normalized = normalize_cve(value)
    if not normalized:
        return []
    parts = [item.strip() for item in normalized.split(",")]
    return [item for item in parts if item]


def sanitize_filename(text):
    invalid_chars = '<>:"/\\|?*'
    result = str(text)
    for ch in invalid_chars:
        result = result.replace(ch, "_")
    return result.strip() or "unknown"


def load_excel(path):
    if not path.exists():
        raise FileNotFoundError(f"未找到文件: {path}")
    return pd.read_excel(path)


def build_data_index(data_df):
    missing_columns = [col for col in REQUIRED_DATA_COLUMNS if col not in data_df.columns]
    if missing_columns:
        raise ValueError(f"DATA.xlsx 缺少列: {missing_columns}")

    indexed = {}
    for _, row in data_df.iterrows():
        cve = normalize_cve(row.get(DATA_CVE_COL))
        if not cve:
            continue
        if cve not in indexed:
            indexed[cve] = row
    return indexed


def write_tmp_json(row):
    TMP_DIR.mkdir(parents=True, exist_ok=True)
    payload = {}
    for col in REQUIRED_DATA_COLUMNS:
        value = row.get(col)
        payload[col] = None if pd.isna(value) else value

    with TMP_JSON_FILE.open("w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)

    return payload


def repo_dir_from_project(repo_name):
    return TARGET_REPO_ROOT / str(repo_name)


def recon_file_from_project(repo_name):
    return RECON_DIR / f"recon_{sanitize_filename(repo_name)}.json"


def output_file_from_repo_cve(repo_name, cve_id):
    repo_dir = VFIND_DIR / sanitize_filename(repo_name)
    repo_dir.mkdir(parents=True, exist_ok=True)
    return repo_dir / f"{sanitize_filename(repo_name)}_{sanitize_filename(cve_id)}.json"


def cvelist_output_path():
    CVELIST_DIR.mkdir(parents=True, exist_ok=True)
    return CVELIST_DIR / "non_empty_sinks.json"


def run_command(cmd):
    print("[INFO] 执行命令:", " ".join(str(item) for item in cmd))
    completed = subprocess.run([str(item) for item in cmd], check=False)
    if completed.returncode != 0:
        print(f"[WARN] 命令执行失败，返回码: {completed.returncode}")
        return False
    return True


def run_recon(repo_name):
    repo_path = repo_dir_from_project(repo_name)
    if not repo_path.exists():
        print(f"[WARN] 仓库目录不存在，跳过 recon: {repo_path}")
        return None

    RECON_DIR.mkdir(parents=True, exist_ok=True)
    recon_file = recon_file_from_project(repo_name)
    cmd = [
        "vuln_reach_analysis",
        "recon",
        "--repo",
        str(repo_path),
        "--out",
        str(recon_file),
        "--format",
        "json",
    ]
    if not run_command(cmd):
        return None
    return recon_file


def run_vfind(repo_name, cve_id, recon_file):
    repo_path = repo_dir_from_project(repo_name)
    if not repo_path.exists():
        print(f"[WARN] 仓库目录不存在，跳过执行命令: {repo_path}")
        return None

    output_name = output_file_from_repo_cve(repo_name, cve_id)
    cmd = [
        "vuln_reach_analysis",
        "vfind",
        "--repo",
        str(repo_path),
        "--bundle",
        str(TMP_JSON_FILE),
        "--recon",
        str(recon_file),
        "--out",
        str(output_name),
        "--format",
        "json",
        "--agent-mode",
        "opencode",
    ]

    if not run_command(cmd):
        return None
    return output_name


def collect_non_empty_sinks(task_items):
    cve_list = []
    for item in task_items:
        path = Path(item["output_file"])
        if not path.exists():
            continue
        try:
            with path.open("r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as exc:
            print(f"[WARN] 读取结果文件失败: {path}, error: {exc}")
            continue

        sinks = data.get("sinks")
        if sinks:
            cve_list.append({
                "repo_name": item["repo_name"],
                "cve_id": item["cve_id"],
                "output_file": str(path),
            })

    output_path = cvelist_output_path()
    output_path.write_text(json.dumps(cve_list, ensure_ascii=False, indent=2), encoding="utf-8")
    print("LIST:", cve_list)
    print(f"[INFO] cvelist 已保存: {output_path}")
    return cve_list


def generate_tasks(result_file=RESULT_FILE, data_file=DATA_FILE):
    result_df = load_excel(Path(result_file))
    data_df = load_excel(Path(data_file))

    if RESULT_CVE_COL not in result_df.columns:
        raise ValueError(f"result.xlsx 缺少列: {RESULT_CVE_COL}")

    data_index = build_data_index(data_df)
    project_to_cves = {}
    for _, result_row in result_df.iterrows():
        project_name = ""
        if RESULT_PROJECT_COL in result_df.columns and not pd.isna(result_row.get(RESULT_PROJECT_COL)):
            project_name = str(result_row.get(RESULT_PROJECT_COL)).strip()
        if not project_name:
            continue

        for cve in split_cve_values(result_row.get(RESULT_CVE_COL)):
            project_to_cves.setdefault(project_name, [])
            if cve not in project_to_cves[project_name]:
                project_to_cves[project_name].append(cve)

    if not project_to_cves:
        print("[INFO] result.xlsx 中没有可处理的 Project/CVE 数据。")
        return []

    processed = 0
    skipped = 0
    task_items = []

    for project_name, cve_values in project_to_cves.items():
        recon_file = run_recon(project_name)
        if recon_file is None:
            skipped += len(cve_values)
            continue

        for cve in cve_values:
            row = data_index.get(cve)
            if row is None:
                print(f"[WARN] DATA.xlsx 中未找到对应 CVE: {cve}")
                skipped += 1
                continue

            payload = write_tmp_json(row)
            cve_id = payload.get("CVE编号")

            if not cve_id:
                print(f"[WARN] 缺少 CVE编号，跳过: {cve}")
                skipped += 1
                continue

            output_path = run_vfind(project_name, str(cve_id), recon_file)
            if output_path is None:
                skipped += 1
                continue

            processed += 1
            task_items.append({
                "repo_name": project_name,
                "cve_id": str(cve_id),
                "recon_file": str(recon_file),
                "output_file": str(output_path),
            })

    cve_list = collect_non_empty_sinks(task_items)
    print(f"[DONE] 完成。成功: {processed}，跳过/失败: {skipped}")
    return cve_list


def main():
    generate_tasks()


if __name__ == "__main__":
    main()