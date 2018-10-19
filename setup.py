import setuptools

with open('README.md', 'r') as fh:
    long_description = fh.read()

setuptools.setup(
    name='fargatespawner',
    version='0.0.15',
    author='Department for International Trade - WebOps',
    author_email='webops@digital.trade.gov.uk',
    description='Spawns JupyterHub single user servers in Docker containers running in AWS Fargate',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/uktrade/fargatespawner',
    packages=setuptools.find_packages(),
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
)
