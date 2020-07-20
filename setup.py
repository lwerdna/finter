# https://packaging.python.org/tutorials/packaging-projects/

import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="finter",
    version="1.0",
    author="Andrew Lamoureux",
    author_email="foo@bar.com",
    description="file interval approach to file dissections",
    long_description=long_description, # load from README.md
    long_description_content_type="text/markdown",
    url="https://github.com/lwerdna/finter",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: Public Domain",
        "Operating System :: OS Independent",
    ],
)

