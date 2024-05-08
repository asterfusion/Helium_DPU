from distutils.core import setup
import py2exe

options = \
		{ \
			'py2exe' : \
			{ \
				'dist_dir': 'DoxygenPreprocessor',
			} \
		}


# for console program use 'console = [{"script" : "scriptname.py"}]
setup(console=[{"script" : "doxygen_preprocessor.py"}],
		name='doxygen_preprocessor',
		description='Doxygen Preprocessor',
		options=options)
