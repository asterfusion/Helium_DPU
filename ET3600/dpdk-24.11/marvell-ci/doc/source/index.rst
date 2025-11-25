=======================================
Marvell DPDK Developer CI Documentation
=======================================

Overview
========

  The following are the different stages in DPDK CI.

.. image:: _static/dpdkci.png
  :alt: DPDK CI

* **Init** - Initializes the environment for running further CI steps.
* **Check** - Runs checkpatch and checkformat. See section `Formatting Checks`_
  for more details.
* **Add Reviewers** - Auto adds reviewers to gerrit review.
* **Build** - Does multiple DPDK builds for different architectures and build
  parameters. See section `Building`_ for more details. This also does the
  Klocwork static analysis. See section `Klocwork`_ for more details.
* **Test** - Runs various DPDK tests. See section `Testing`_ for more details.
* **Verification** - Verifies the complete CI run and make sure that all
  required tests/builds has been completed.

--------------------------------------------------------------------------------

CI Directives
=============

  There are some directives that can be passed in the commit message or gerrit
  comments to control the CI behaviour. When passing in commit message the
  directive needs to be given in separate line starting with the ``ci:``
  keyword. When passing in gerrit commit, the directive can be present anywhere
  in the comment provided that the comment has ``@devcit`` keyword.

--------------------------------------------------------------------------------

Formatting Checks
=================

How to run formatting checks ?
------------------------------
  To do checkpatch, run the following.

  ::

    ./marvell-ci/checkpatch/run_checkpatch.sh

  To do checkformat, run the following.

  ::

    ./marvell-ci/checkpatch/run_checkformat.sh

How to skip format checks in CI ?
---------------------------------
  In rare cases, checkpatch/checkformat may give some warnings/errors whose
  rectifications may not absorbable into the code. In such instances, user can
  add the CI directives ``skip_checkpatch`` and ``skip_checkformat`` for
  skipping checkpatch and checkformat respectively.

  **Note:** When checkpatch or checkformat is skipped in CI, the stage is still
  run but the result is ignored.

--------------------------------------------------------------------------------

Klocwork
========

How to run klocwork ?
---------------------
  To do klocwork, run the following.

  ::

    export BUILDROOT=/path/to/build/dir
    export PROJROOT=/path/to/dpdk/src
    ./marvell-ci/klocwork/klocwork.sh -r $BUILDROOT -p $PROJROOT

  where ``BUILDROOT`` is the directory where the klocwork build will be done and
  ``PROJROOT`` is the path to dpdk source root (Default value is ``PWD``). After
  the script is executed successfully, the klocwork report will be created in
  the current directory as ``kwreport-detailed.txt``.

  **Note:** Before running the klocwork script, make sure that klocwork binaries
  like ``kwinject``, ``kwcheck`` etc. are available in the ``PATH``.

How to skip klocwork in CI ?
----------------------------
  In cases where we need to skip klocwork in CI, the directive ``skip_klocwork``
  can be used.

--------------------------------------------------------------------------------

Building
========

  The build framework is implemented under ``marvell-ci/build`` directory. The
  different build options available are listed as env files under
  ``marvell-ci/build/env`` directory. The parameters necessary for a build are
  defined in these env files.

How to build ?
--------------
  To trigger a build, run the following.

  ::

    export BUILDROOT=/path/to/build/dir
    export PROJROOT=/path/to/dpdk/src
    export ENVFILE=/path/to/env file
    ./marvell-ci/build/build.sh -r $BUILDROOT -b $ENVFILE -p $PROJROOT

  where ``BUILDROOT`` is the directory where the klocwork build will be done,
  ``ENVFILE`` is the env file (Eg. ``marvell-ci/build/env/armv8-gcc.env``) and
  ``PROJROOT`` is the path to dpdk source root (Default value is ``PWD``).

  This command triggers the meson build and ninja build commands with the
  parameters defined in the env file. Additional parameters to meson build
  can be given using the ``-m`` parameter to build script.

  Once script is completed successfully, build is available under
  ``BUILDROOT/build`` and dpdk is installed under ``BUILDROOT/prefix``.

How to skip build in CI ?
-------------------------
  Builds can be skipped in CI using the directives ``skip_test_build`` and
  ``skip_doc_build`` directives.

  | **Note:** If builds are skipped, CI will not give +1.

Handling exe_wrapper in test builds
-----------------------------------
  The ``exe_wrapper`` property needs to be defined in the cross file for test
  builds as this is used later in ``meson test`` (See section `Testing`_ for
  more details). But the ``exe_wrapper`` also gets called during meson build.
  Since we don't want any kind of test step to be performed during build stage,
  an empty exe_wrapper script is created prior to calling ``meson`` in the build
  script. For this purpose the ``BUILD_SETUP_CMD`` is defined in the env file
  which does the required pre-build setup.

  **Note:** Users may also prefer running ``meson build`` without going through
  the CI build script. For this use case, the exe_wrapper property is kept
  commented by default in the cross files. The ``BUILD_SETUP_CMD`` does the
  additional job of uncommenting this line.

--------------------------------------------------------------------------------

Testing
=======
  The test framework is implemented under ``marvell-ci/test`` directory. The
  different test options available are listed as env files under
  ``marvell-ci/test/env`` directory. The parameters necessary for a test are
  defined in these env files. Currently there are three testing modes available
  * Board
  * ASIM
  * Emulator

  **Note:** Emulator mode only creates a cn10k disk image with a self contained
  exhaustive test script which can be directly run on emulator.

Testing Method
--------------
  CI tests are run in two stages. Initially a test list is created using the
  ``exe_wrapper`` script defined in the cross config files. The ``exe_erapper``
  script used is available in ``marvell-ci/test/common/exe_wrapper.sh``. The
  test list creation happens during the ``meson test`` context and once ``meson
  test`` completes, this test list is read by the ``TEST_RUN_CMD`` defined in
  the env file and appropriate test commands are launched on the target.

  **Note:** Helper functions to handle and manipulate the test list is available
  in ``marvell-ci/test/common/test_list_helper_funcs.sh``.

How to run tests ?
------------------
Running on board
****************
  To run tests on a board, use the following commands.

  ::

    export TARGET_BOARD=user@ip
    export BUILDROOT=/path/to/build/dir
    export PROJROOT=/path/to/dpdk/src
    export ENVFILE=$PROJROOT/marvell-ci/test/env/cn9k.env
    ./marvell-ci/test/test.sh -r $BUILDROOT -t $ENVFILE -p $PROJROOT

  where ``BUILDROOT`` is the directory where the build is available, ``ENVFILE``
  is the cn9k test env file, ``PROJROOT`` is the path to dpdk source root
  (Default value is ``PWD``) and ``TARGET_BOARD`` is the SSH username and IP
  address of the target board.

  | **Note:** The ``BUILDDIR`` needs to be the same directory as given to the
    ``build.sh`` script during the build stage.
  | **Note:** The SSH user defined in ``TARGET_BOARD`` is expected to have
    passwordless SSH and passwordless sudo permissions on the target board.


Running on ASIM
***************
  To run tests on ASIM, use the following commands.

  ::

    export TARGET_ASIM=user@ip
    export ASIM=/remote/path/to/asim
    export BUILDROOT=/path/to/build/dir
    export PROJROOT=/path/to/dpdk/src
    export ENVFILE=$PROJROOT/marvell-ci/test/env/asim-cn10ka.env
    ./marvell-ci/test/test.sh -r $BUILDROOT -t $ENVFILE -p $PROJROOT

  where ``BUILDROOT`` is the directory where the build is available, ``ENVFILE``
  is the cn10k asim test env file, ``PROJROOT`` is the path to dpdk source root
  (Default value is ``PWD``), ``TARGET_ASIM`` is the SSH username and IP address
  of the ASIM host and ``ASIM`` is the directory where the ASIM binary is
  available on the ASIM host.

  | **Note:** The ``BUILDDIR`` needs to be the same directory as given to the
    ``build.sh`` script during the build stage.
  | **Note:** The SSH user defined in ``TARGET_ASIM`` is expected to have
    passwordless SSH and passwordless sudo permissions on the ASIM host.

How to skip / run tests in CI ?
-------------------------------
  Only base tests defined in the groovy files are run by default and that too
  tests are run only on the top most commit of a review series. If this
  behaviour needs to be changed, the directive ``skip_test`` can be given to
  force skip all tests. To force run a test, then directive ``run_TEST_NAME``
  can be given where ``TEST_NAME`` is the name of the test stage. For eg: to run
  ``test-cn9k`` test stage directive ``run_test-cn9k`` can be given.

  **Note:** If mandatory tests are skipped CI will not give +1.

--------------------------------------------------------------------------------

Adding new CNXK test cases
==========================
  Example cnxk test cases are present in the ``sample`` and ``l2fwd_simple``
  directories under the ``marvell-ci/test/cnxk-tests`` directory.

  To add a new test case, create the new test directory under
  ``marvell-ci/test/cnxk-tests`` and add it to the ``test_subdirs`` list in
  ``marvell-ci/test/cnxk-tests/meson.build``.

  Under the new test directory create a ``meson.build`` file following the
  format in ``marvell-ci/tests/cnxk-tests/sample/meson.build``. Populate the
  ``test_script``, ``test_name``, ``test_dir`` and ``test_args`` variables
  appropriately. Any file that is required for the test case should be copied to
  the build directory using the command ``run_command(copy_data, FILENAME)`` in
  ``meson.build`` file. The test itself should be described using the meson
  ``test`` directive. If you need the test to be available in the install
  directory as well, use the ``install_data`` directive appropriately.

  The CI will first change directory to ``test_dir`` and will call the
  ``test_script`` giving ``test_args`` as the arguments.

  **Note:** ``test-dir`` must be an absolute path within the build directory. CI
  performs a string substitution on this path to determine the path on the
  target.

  The user must take care that the ``test_script`` is self contained and must
  not have any other external dependencies. Any kind of dependencies on input
  files, config files etc. must be taken care by copying those files into the
  test directory and by making sure that these are copied into the build
  directory as well using the ``run_command(copy_data, FILENAME)`` directive in
  the ``meson.build``.

  **Note:** Helper functions for ``testpmd`` and some other pcap helper routines
  are present in the ``marvell-ci/tests/cnxk-tests/common`` directory. Example
  usages of these helper functions can be seen in the ``l2fwd_simple`` test.

--------------------------------------------------------------------------------

Running Marvell CI scripts in other DPDK branches
=================================================

  The Marvell CI scripts can be run on any DPDK branch by copying the entire
  ``marvell-ci`` directory to the new branch.

  To enable build and run of CNXK specific test cases, the following line needs
  to be added to the top level ``meson.build``.

  ``subdir('marvell-ci/test/cnxk-tests')``

  **Note:** Build failures that occur due to ``meson`` build infrastructure
  changes in different branches needs to be taken care by the user.
