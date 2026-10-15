from setuptools import setup, find_packages

setup(
    name="netroute",
    version="1.0.0",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    python_requires=">=3.9",
    install_requires=[],
    entry_points={
        "console_scripts": [
            "netroute = netroute.cli:main",
        ],
    },
)
