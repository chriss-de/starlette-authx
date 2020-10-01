import os
import setuptools

here = os.path.abspath(os.path.dirname(__file__))

with open(os.path.join(here, 'README.md'), 'r') as fh:
    long_description = fh.read()


setuptools.setup(
    name='starlette-authx',
    version='0.0.7',
    long_description=long_description,
    long_description_content_type="text/markdown",
    author='Christoph Hartmann',
    author_email='mail_to_chriss@posteo.net',
    url='https://github.com/chriss-de/starlette-authx',
    packages=setuptools.find_packages(),
    python_requires='>=3.7',
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    install_requires=[
        'starlette>=0.12,<1',
        'python-jose>=3,<4',
        'passlib>=1,<2',
        'jinja2>=2,<3',
    ],
    extras_require={
        'gql': ['graphene>2.1,<3'],
        'fastapi': ['fastapi>=0.54,<1'],
    },
)
