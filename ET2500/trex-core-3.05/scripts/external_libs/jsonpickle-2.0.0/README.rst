.. image:: https://img.shields.io/pypi/v/jsonpickle.svg
   :target: `PyPI link`_

.. image:: https://img.shields.io/pypi/pyversions/jsonpickle.svg
   :target: `PyPI link`_

.. _PyPI link: https://pypi.org/project/jsonpickle

.. image:: https://dev.azure.com/jaraco/jsonpickle/_apis/build/status/jaraco.jsonpickle?branchName=master
   :target: https://dev.azure.com/jaraco/jsonpickle/_build/latest?definitionId=1&branchName=master

.. image:: https://readthedocs.org/projects/jsonpickle/badge/?version=latest
   :target: https://jsonpickle.readthedocs.io/en/latest/?badge=latest

.. image:: https://travis-ci.org/jsonpickle/jsonpickle.svg?branch=master
   :target: https://travis-ci.org/jsonpickle/jsonpickle
   :alt: travis

.. image:: https://img.shields.io/badge/License-BSD%203--Clause-blue.svg
   :target: https://github.com/jsonpickle/jsonpickle/blob/master/COPYING
   :alt: BSD


jsonpickle
==========
jsonpickle is a library for the two-way conversion of complex Python objects
and `JSON <http://json.org/>`_.  jsonpickle builds upon the existing JSON
encoders, such as simplejson, json, and demjson.

For complete documentation, please visit the
`jsonpickle documentation <http://jsonpickle.readthedocs.io/>`_.

Bug reports and merge requests are encouraged at the
`jsonpickle repository on github <https://github.com/jsonpickle/jsonpickle>`_.

jsonpickle supports Python 2.7 and Python 3.4 or greater.

    **WARNING**:
    jsonpickle can execute arbitrary Python code. Do not load jsonpickles from untrusted / unauthenticated sources.

Why jsonpickle?
===============
Data serialized with python's pickle (or cPickle or dill) is not easily readable outside of python. Using the json format, jsonpickle allows simple data types to be stored in a human-readable format, and more complex data types such as numpy arrays and pandas dataframes, to be machine-readable on any platform that supports json. E.g., unlike pickled data, jsonpickled data stored in an Amazon S3 bucket is indexible by Amazon's Athena.

Install
=======

Install from pip for the latest stable release:

::

    pip install jsonpickle

Install from github for the latest changes:

::

    pip install git+https://github.com/jsonpickle/jsonpickle.git

If you have the files checked out for development:

::

    git clone https://github.com/jsonpickle/jsonpickle.git
    cd jsonpickle
    python setup.py develop


Numpy Support
=============
jsonpickle includes a built-in numpy extension.  If would like to encode
sklearn models, numpy arrays, and other numpy-based data then you must
enable the numpy extension by registering its handlers::

    >>> import jsonpickle.ext.numpy as jsonpickle_numpy
    >>> jsonpickle_numpy.register_handlers()

Pandas Support
==============
jsonpickle includes a built-in pandas extension.  If would like to encode
pandas DataFrame or Series objects then you must enable the pandas extension
by registering its handlers::

    >>> import jsonpickle.ext.pandas as jsonpickle_pandas
    >>> jsonpickle_pandas.register_handlers()

jsonpickleJS
============
`jsonpickleJS <https://github.com/cuthbertLab/jsonpickleJS>`_
is a javascript implementation of jsonpickle by Michael Scott Cuthbert.
jsonpickleJS can be extremely useful for projects that have parallel data
structures between Python and Javascript.

License
=======
Licensed under the BSD License. See COPYING for details.
See jsonpickleJS/LICENSE for details about the jsonpickleJS license.

Development
===========

Use `make` to run the unit tests::

        make test

`pytest` is used to run unit tests internally.

A `tox` target is provided to run tests using tox.
Setting ``multi=1`` tests using all installed and supported Python versions::

        make tox
        make tox multi=1

`jsonpickle` itself has no dependencies beyond the Python stdlib.
`tox` is required for testing when using the `tox` test runner only.

The testing requirements are specified in `requirements-dev.txt`.
It is recommended to create a virtualenv and run tests from within the
virtualenv, or use a tool such as `vx <https://github.com/davvid/vx/>`_
to activate the virtualenv without polluting the shell environment::

        python3 -mvenv env3x
        vx env3x pip install --requirement requirements-dev.txt
        vx env3x make test

`jsonpickle` supports multiple Python versions, so using a combination of
multiple virtualenvs and `tox` is useful in order to catch compatibility
issues when developing.
