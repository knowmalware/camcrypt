# Copyright (c) 2013, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

from setuptools import Extension, setup, find_packages

import camcrypt

setup(
    name="camcrypt",
    version=camcrypt._VERSION,
    author="Frank Poz",
    author_email="knowmalware@gmail.com",
    description="Python wrapper around the Camellia encryption library",
    url="http://github.com/knowmalware/camcrypt",
    packages=['camcrypt'],
    ext_modules=[Extension(
        name='camcrypt.camellia',
        sources=['camellia-GPL-1.2.0/camellia.c'],
        include_dirs=['camellia-1.2.0'],
        )
    ],
    classifiers=[
        "Programming Language :: Python",
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Operating System :: OS Independent",
    ]
)
