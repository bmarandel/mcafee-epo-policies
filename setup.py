import setuptools

with open("README.md", "r") as fh:
	long_description = fh.read()

setuptools.setup(
	name="mcafee_epo_policies",
	version="0.0.7",
	author="Benjamin Marandel",
	license="Apache License 2.0",
	platforms="any",
	description="McAfee ePolicy Orchestrator Policies Python Class Library",
	long_description=long_description,
	long_description_content_type="text/markdown",
	url="https://github.com/bmarandel/mcafee-epo-policies",
	packages=setuptools.find_packages(),
	include_package_data=True,
	classifiers=[
		"Development Status :: 3 - Alpha",
		"Intended Audience :: System Administrators",
		"Operating System :: OS Independent",
		"License :: OSI Approved :: Apache Software License",
		"Topic :: Software Development :: Libraries :: Python Modules",
		"Programming Language :: Python :: 3.6",
		"Programming Language :: Python :: 3.7",
		"Programming Language :: Python :: 3.8",
	],
)
