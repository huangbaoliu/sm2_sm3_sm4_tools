#coding:utf-8

import os
import sys
from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))

readme_file = os.path.join(here, 'README.md')

def read_text(file_path):
    """
    fix the default operating system encoding is not utf8.
    """
    if sys.version_info.major < 3:
        with open(file_path) as f:
            return f.read()
    with open(file_path, encoding="utf8") as f:
        return f.read()

README = read_text(os.path.join(here, 'README.md'))

requires = [

]

test_requirements = [

]


setup(
    name='sm_tools',
    description='Pure-Python SM2/SM3/SM4 implementation',
    version='1.0.0',
    author='huangbaoliu',
    author_email='liuhuangbao@126.com',
    packages=find_packages(),
    include_package_data=True,
    long_description=README,
    url='https://github.com/huangbaoliu/sm2_sm3_sm4_tools',
    platforms='all platform',
    license='BSD',
)
