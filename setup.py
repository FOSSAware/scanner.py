from setuptools import setup, find_packages

from os import path
this_directory = path.abspath(path.dirname(__file__))
with open(path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name="scanoss-scanner",
    version="1.4.0",
    author="SCANOSS",
    author_email="info@scanoss.com",
    description='Simple Python library to use the SCANOSS API.',
    long_description=long_description,
    long_description_content_type='text/markdown',
    tests_require=["pytest", "grappa"],
    install_requires=["requests", "crc32c",
                      "binaryornot"],
    include_package_data=True,
    entry_points={
        'console_scripts': ['scanner.py=scanner:main'],
    },
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent"
    ],
    python_requires='>=3.5'
)
