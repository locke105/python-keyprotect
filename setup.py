import setuptools

setuptools.setup(
    name = "python-keyprotect",
    version = "0.1.1",
    url = "https://github.com/locke105/python-keyprotect",
    author = "Mathew Odden",
    author_email = "mathewrodden@gmail.com",
    packages = setuptools.find_packages(),
    install_requires = [
        'requests'
    ]
)
