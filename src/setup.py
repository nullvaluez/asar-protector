from setuptools import setup, Extension
from node_gyp_build import build

setup(
    name='asarproof',
    version='0.1.0',
    ext_modules=[
        Extension(
            'binding',
            sources=['native/src/encryption.cpp', 'native/src/utils.cpp'],
            include_dirs=['/usr/local/opt/openssl/include', '/usr/local/include'],
            libraries=['crypto', 'ssl', 'sodium'],
            library_dirs=['/usr/local/opt/openssl/lib'],
            define_macros=[('NAPI_VERSION', 6)],
            extra_compile_args=['-fno-exceptions']
        )
    ],
    cmdclass={'build': build}
)