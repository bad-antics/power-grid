from setuptools import setup,find_packages
setup(name="power-grid",version="2.0.0",author="bad-antics",description="Power grid security assessment and simulation",packages=find_packages(where="src"),package_dir={"":"src"},python_requires=">=3.8")
