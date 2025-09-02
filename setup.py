from setuptools import setup, find_packages

def read_version():
    ns = {}
    with open("logq/__version__.py") as f:
        exec(f.read(), ns)
    return ns["__version__"]

setup(
    name="logq",
    version=read_version(),
    packages=find_packages(),
    python_requires=">=3.10",
    entry_points={
        "console_scripts": ["logq = logq.cli:main"],
    },
    description="Command-line log analyser (mostly for security purposes)",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="Yaroslav Polyakov",
    author_email="yaroslaff@gmail.com",
    license="MIT",
    install_requires=[
        "evalidate>=2.0.5",
        "rich"
    ],
)
