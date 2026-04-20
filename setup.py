from setuptools import setup

setup(
    name="cmdmap",
    version="1.0.0",
    description="Autonomous Command Injection Detector (CMDINJ)",
    author="L4ZZ3RJ0D",
    url="https://github.com/project-hellhound/cmdmap",
    py_modules=["CMDmap"],
    python_requires=">=3.10",
    install_requires=[],
    entry_points={
        "console_scripts": [
            "cmdmap=CMDmap:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Operating System :: OS Independent",
    ],
)
