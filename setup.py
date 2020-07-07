#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup

project = "conmon"

setup(
    name=project,
    version="0.1.0",
    description="Run conan as monitored process.",
    long_description="Run conan as monitored process.",
    author="flashdagger",
    author_email="flashdagger@googlemail.com",
    license="MIT",
    url="https://github.com/flashdagger/conmon",
    platforms="any",
    packages=[project],
    entry_points={
        "console_scripts": [f"{project.replace('_', '-')}={project}.__main__:main"]
    },
    include_package_data=True,
    # project dependencies for installation
    python_requires=">=3.6",
    install_requires=["psutil>=5.7", "colorlog>=4.1"],
    setup_requires=["pytest-runner"],
    tests_require=["pytest"],
    test_suite="tests",
    zip_safe=False,
    keywords="",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "License :: OSI Approved :: MIT License",
        "Intended Audience :: Developers",
        "Natural Language :: English",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
    ],
)
