import setuptools
import os

setuptools.setup(
    name="os-tests",
    version="0.0.31",
    author="Xiao Liang",
    author_email="xiliang@redhat.com",
    description="Lightweight, fast check and tests collection for Linux OS",
    long_description=open('README.md').read(),
    long_description_content_type="text/markdown",
    url="https://github.com/liangxiao1/os-tests",
    #packages=setuptools.find_packages(),
    packages=[ 'os_tests', 'os_tests.tests', 'os_tests.libs'],
    package_data={
        'os_tests': [
            'cfg/*',
            'data/*',
            'templates/*'
        ]
    },
    include_package_data=True,
    #data_files=[('/'+os.path.expanduser("~"), ['cfg/os-tests.yaml']),],
    install_requires=['PyYAML', 'argparse', 'Jinja2'],
    license="GPLv3+",
    classifiers=[
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
        "Programming Language :: Python :: 3",
        'Operating System :: POSIX',

    ],
    python_requires='>=3.6',
    entry_points = {
             'console_scripts': [
                 'os-tests = os_tests.os_tests_all:main',
             ],
         },
)
