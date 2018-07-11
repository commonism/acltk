from distutils.core import setup

setup(name='acltk',
      version='0.2',
      description='Cisco, OPNSense, pfSense ACL processing toolkit',
      author='Markus Koetter',
      author_email='koetter@luis.uni-hannover.de',
      url='..',
      packages=['acltk'],
      package_dir = {'acltk': 'lib'},
      requires=['tatsu','jinja2']
)