
from setuptools import setup

setup(
        name="hillstone-client",
        version="1.0.0",
        description="Simple Hillstone client for linux",
        url="https://github.com/dankernel/hilldust",
        author="dankernel, dsparch",
        author_email="dkdkernel@gmail.com",
        licencs="GPL3.0",
        packages=["hillstone_client"],
        zip_safe=False,
        install_requires=[
            "cryptography==36.0.1", 
            "scapy==2.4.5"
        ],
        scripts=["hillstone_client/hillstone-client"],
        python_requires='>=3.8',
)





