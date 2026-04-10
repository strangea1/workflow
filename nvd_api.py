import argparse
import json
import re
import time
from pathlib import Path

import requests

# NVD API 配置
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OUTPUT_DIR = Path("workflow_output/nvd")
DEFAULT_CVE_FILE = Path("code/cve.json")
REQUEST_TIMEOUT = 30
RETRY_TIMES = 3
RETRY_SLEEP_SECONDS = 2


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="通过 NVD API 抓取 CVE 并统一导出为 JSON")
    parser.add_argument(
        "--cve-file",
        default=str(DEFAULT_CVE_FILE),
        help="CVE 列表文件，支持 .json/.txt；默认读取 code/cve.json",
    )
    parser.add_argument(
        "--output-dir",
        default=str(OUTPUT_DIR),
        help="输出目录，默认 code/output/nvd_api",
    )
    return parser.parse_args()


def load_cve_list(cve_file: str | None) -> list[str]:
    if not cve_file:
        return []

    path = Path(cve_file)
    if not path.exists():
        raise FileNotFoundError(f"CVE 列表文件不存在: {path}")

    if path.suffix.lower() == ".json":
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            data = data.get("CVE_LIST") or data.get("cve_list") or []
        if not isinstance(data, list):
            raise ValueError("JSON CVE 列表文件格式错误，应为数组或包含 CVE_LIST/cve_list 的对象")
        return [str(item).strip() for item in data if str(item).strip()]

    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def sanitize_filename(text: str) -> str:
    return re.sub(r'[^A-Za-z0-9._-]+', '_', str(text)).strip("._") or "unknown"


def fetch_cve_detail(cve_id: str) -> dict:
    """通过 NVD API 获取单个 CVE 详情。"""
    params = {"cveId": cve_id}
    last_error = None

    for attempt in range(1, RETRY_TIMES + 1):
        try:
            response = requests.get(NVD_API_URL, params=params, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as exc:
            last_error = exc
            print(f"[WARN] 获取 {cve_id} 失败（第 {attempt}/{RETRY_TIMES} 次）：{exc}")
            if attempt < RETRY_TIMES:
                time.sleep(RETRY_SLEEP_SECONDS)

    raise RuntimeError(f"获取 {cve_id} 失败：{last_error}")


def build_nvd_output_path(output_dir: Path, repo_name: str, cve_id: str) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    file_name = f"{sanitize_filename(repo_name)}_{sanitize_filename(cve_id)}_nvd.json"
    return output_dir / file_name


def save_cve_detail(cve_id: str, data: dict, output_dir: Path, repo_name: str | None = None) -> Path:
    """将单个 CVE 详情保存为 JSON 文件。"""
    output_dir.mkdir(parents=True, exist_ok=True)
    if repo_name:
        output_file = build_nvd_output_path(output_dir, repo_name, cve_id)
    else:
        output_file = output_dir / f"{cve_id}.json"
    output_file.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return output_file


def fetch_and_save_cve_detail(cve_id: str, output_dir: Path, repo_name: str | None = None) -> Path:
    data = fetch_cve_detail(cve_id)
    return save_cve_detail(cve_id, data, output_dir, repo_name=repo_name)


def fetch_and_save_cve_list(items: list[dict], output_dir: str | Path) -> dict:
    target_dir = Path(output_dir)
    results = []
    failed = []
    for item in items:
        repo_name = str(item.get("repo_name", "")).strip() or "unknown"
        cve_id = str(item.get("cve_id", "")).strip()
        if not cve_id.startswith("CVE-"):
            failed.append({"repo_name": repo_name, "cve_id": cve_id, "reason": "非法 CVE 编号"})
            continue
        try:
            data = fetch_cve_detail(cve_id)
            saved_path = save_cve_detail(cve_id, data, target_dir, repo_name=repo_name)
            results.append({
                "repo_name": repo_name,
                "cve_id": cve_id,
                "file": str(saved_path),
            })
            print(f"[OK] {repo_name} / {cve_id} 已保存到 {saved_path}")
            time.sleep(0.6)
        except Exception as exc:
            print(f"[ERROR] {repo_name} / {cve_id} 处理失败：{exc}")
            failed.append({"repo_name": repo_name, "cve_id": cve_id, "reason": str(exc)})
    summary_path = save_summary(results, failed, target_dir)
    return {"results": results, "failed": failed, "summary_path": str(summary_path)}


def save_summary(results: list[dict], failed: list[dict], output_dir: Path) -> Path:
    summary = {
        "source": "nvd_api",
        "total": len(results) + len(failed),
        "success": len(results),
        "failed": len(failed),
        "results": results,
        "failed_items": failed,
    }
    summary_path = output_dir / "nvd_api_results.json"
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    return summary_path


def main() -> None:
    args = parse_args()
    cve_list = load_cve_list(args.cve_file)
    output_dir = Path(args.output_dir)

    if not cve_list:
        print("[INFO] CVE 列表为空，请先在 code/cve.json 中填写需要查询的 CVE 编号。")
        return

    results = []
    failed = []
    for cve_id in cve_list:
        cve_id = str(cve_id).strip()
        if not cve_id.startswith("CVE-"):
            print(f"[SKIP] 非法 CVE 编号：{cve_id}")
            failed.append({"cve_id": cve_id, "reason": "非法 CVE 编号"})
            continue

        try:
            result = fetch_cve_detail(cve_id)
            saved_path = save_cve_detail(cve_id, result, output_dir)
            results.append({
                "cve_id": cve_id,
                "file": str(saved_path),
                "data": result,
            })
            print(f"[OK] {cve_id} 已保存到 {saved_path}")
            time.sleep(0.6)
        except Exception as exc:
            print(f"[ERROR] {cve_id} 处理失败：{exc}")
            failed.append({"cve_id": cve_id, "reason": str(exc)})

    summary_path = save_summary(results, failed, output_dir)
    print(f"[OK] 汇总结果已保存到 {summary_path}")


if __name__ == "__main__":
    main()
