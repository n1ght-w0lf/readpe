import setuptools

with open("README.md", "r") as f:
    long_description = f.read()

setuptools.setup(
    name="readpe",
    version="0.1",
    description="A cross platform tool to work with PE files from the command line.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    license="MIT",
    classifiers=[
        "Environment :: Console",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    author="Abdallah Elshinbary",
    author_email="abdallahelshinbary82@gmail.com",
    url="https://github.com/N1ght-W0lf/readpe",
    packages=setuptools.find_packages(),
    install_requires=[
        'pefile>=2019.4.18',
        'tabulate>=0.8.6',
    ],
    entry_points={
        'console_scripts': [
            'readpe = readpe.readpe:main'
        ],
    }
)
