# Build the C-speed kernel:  python setup_kernel.py build_ext --inplace
# Needs: cython, and libgmp headers (Debian/WSL: sudo apt install libgmp-dev).
from setuptools import setup, Extension
from Cython.Build import cythonize

setup(
    ext_modules=cythonize(
        [Extension("nier_kernel", ["nier_kernel.pyx"], libraries=["gmp"],
                   extra_compile_args=["-O3"])],
        compiler_directives={"language_level": 3},
    ),
)
