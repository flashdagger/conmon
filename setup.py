#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup

project = "git2ptc"

setup(
    name=project,
    version="0.11.1",
    description="Transfer git commits as PTC checkpoints.",
    long_description="Transfer git commits as PTC checkpoints.",
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
    install_requires=["pytegrity==0.45.*", "tqdm==4.45.*"],
    setup_requires=["pytest-runner"],
    tests_require=["pytest"],
    test_suite="tests",
    zip_safe=False,
    keywords="",
    classifiers=[
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: MIT License",
        "Intended Audience :: Developers",
        "Natural Language :: English",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
    ],
)
