import builtins
import os
import subprocess
import sys
from pathlib import Path


TARGET_REPO_ROOT = Path("target_repo")

SPECIAL_TOKENS = ["<|endoftext|>", "<|bos|>", "<|eos|>"]

ALLOWED_EXTENSIONS = {
    ".py", ".md", ".txt", ".json", ".yaml", ".yml"
}

SKIP_DIRS = {
    ".git", "__pycache__", "node_modules", "venv",
    "build", "dist", ".idea", ".vscode"
}

SKIP_FILES = {
    "pyproject.toml", "poetry.lock", "Pipfile", "Pipfile.lock"
}


def sanitize_repo_name(repo_url: str) -> str:
    name = repo_url.rstrip("/").split("/")[-1]
    if name.endswith(".git"):
        name = name[:-4]
    return name or "unknown_repo"


def clone_repo(repo_url: str, clone_root: str | Path = TARGET_REPO_ROOT) -> Path:
    clone_root = Path(clone_root)
    clone_root.mkdir(parents=True, exist_ok=True)
    repo_name = sanitize_repo_name(repo_url)
    repo_dir = clone_root / repo_name

    if repo_dir.exists():
        print(f"[INFO] Repo exists, pulling latest: {repo_dir}")
        subprocess.run(["git", "-C", str(repo_dir), "pull"], check=True)
    else:
        print(f"[INFO] Cloning repo to {repo_dir} ...")
        subprocess.run(["git", "clone", repo_url, str(repo_dir)], check=True)

    return repo_dir

# ========= Step 2: 清洗 =========
def is_target_file(filepath):
    filename = os.path.basename(filepath)
    if filename in SKIP_FILES:
        return False
    _, ext = os.path.splitext(filepath)
    return ext.lower() in ALLOWED_EXTENSIONS


def clean_repo(root_dir: str | Path) -> None:
    root_dir = str(root_dir)
    print(f"[INFO] Cleaning repo...")

    for root, dirs, files in os.walk(root_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        for file in files:
            filepath = os.path.join(root, file)

            if not is_target_file(filepath):
                continue

            try:
                with open(filepath, "rb") as f:
                    raw = f.read()

                text = raw.decode("utf-8", errors="ignore")

                for token in SPECIAL_TOKENS:
                    text = text.replace(token, "")

                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(text)

                print(f"[CLEANED] {filepath}")

            except Exception as e:
                print(f"[SKIP] {filepath} - {e}")


def patch_open() -> None:
    _original_open = open

    def safe_open(*args, **kwargs):
        mode = "r"

        if len(args) >= 2:
            mode = args[1]
        elif "mode" in kwargs:
            mode = kwargs["mode"]

        if "b" not in mode:
            if "encoding" not in kwargs:
                kwargs["encoding"] = "utf-8"
                kwargs["errors"] = "ignore"

        return _original_open(*args, **kwargs)

    builtins.open = safe_open


def patch_tiktoken() -> None:
    try:
        import tiktoken
        orig_encode = tiktoken.Encoding.encode

        def safe_encode(self, text, *args, **kwargs):
            return orig_encode(self, text, disallowed_special=())

        tiktoken.Encoding.encode = safe_encode
    except:
        pass


def run_codewiki(repo_dir: str | Path) -> None:
    repo_dir = Path(repo_dir)
    print(f"[INFO] Running CodeWiki in {repo_dir} ...")

    # 设置环境变量（避免编码问题）
    os.environ["PYTHONUTF8"] = "1"

    from codewiki.cli.main import cli

    # 记录当前目录
    original_dir = Path.cwd()
    original_argv = list(sys.argv)
    original_exit = sys.exit

    try:
        os.chdir(repo_dir)
        print(f"[INFO] Changed directory to: {Path.cwd()}")
        sys.argv = ["codewiki", "generate"]

        def _safe_exit(code=0):
            raise SystemExit(code)

        sys.exit = _safe_exit
        try:
            cli()
        except SystemExit as exc:
            if exc.code not in (0, None):
                raise

    finally:
        sys.exit = original_exit
        sys.argv = original_argv
        os.chdir(original_dir)
        print(f"[INFO] Returned to: {original_dir}")


def prepare_and_run_codewiki(repo_url: str, clone_root: str | Path = TARGET_REPO_ROOT) -> Path:
    repo_dir = clone_repo(repo_url, clone_root)
    clean_repo(repo_dir)
    patch_open()
    patch_tiktoken()
    run_codewiki(repo_dir)
    return repo_dir


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit("用法: python run_codewiki_pipline.py <repo_url>")
    prepare_and_run_codewiki(sys.argv[1])