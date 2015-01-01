from distutils.core import setup

setup(name='acltk',
      version='0.1',
      description='Cisco ACL parsing and filtering tookit',
      author='Markus Koetter',
      author_email='koetter@rrzn.uni-hannover.de',
      url='..',
      packages=['acltk'],
      package_dir = {'acltk': 'lib'},
      requires=['grako']
)