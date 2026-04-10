"""Setup script for vuln-reach-analysis. Metadata and entry points are in pyproject.toml."""
from setuptools import setup, find_packages

if __name__ == "__main__":
    setup(
        packages=find_packages("src"),
        package_dir={"": "src"},
        py_modules=["cli"],
    )
