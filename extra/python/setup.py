import glob
from distutils.core import setup, Extension


netmap_bindings_module = Extension('netmap',
            include_dirs = ['../../sys'],
            sources = glob.glob('*.c'),
            extra_compile_args = [])

setup(name = 'NetmapBindings',
        version = '11.0',
        description = 'python bindings for netmap',
        author = 'Vincenzo Maffione',
        author_email = 'v.maffione@gmail.com',
        url = 'http://info.iet.unipi.it/~luigi/netmap/',
        ext_modules = [netmap_bindings_module])
