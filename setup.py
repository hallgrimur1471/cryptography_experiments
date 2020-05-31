# pylint: disable=invalid-name
import setuptools

with open("README.md", "r") as readme_file:
    long_description = readme_file.read()

setuptools.setup(
    name="drvn.cryptography",
    author="Hallgrimur David Egilsson",
    author_email="hallgrimur1471@gmail.com",
    description="",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/hallgrimur1471/cryptography_experiments",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: POSIX :: Linux",
    ],
    python_requires=">=3.8",
    package_dir={"": "src"},
    packages=setuptools.find_namespace_packages(where="src"),
    package_data={"": ["*", ".*"]},
    entry_points={
        "console_scripts": [
            "drvn_cryptography_run_cryptopals_challenge = "
            + "drvn."
            + "cryptography_challenges."
            + "_entry_point_script:"
            + "main"
        ]
    },
    install_requires=["pycryptodome", "cryptography"],
)
