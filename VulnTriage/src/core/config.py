def load_config(log_level: str = "info", config_path: str | None = None) -> dict:
    cfg = {"log_level": log_level}
    if config_path:
        cfg["config_path"] = config_path
    return cfg
