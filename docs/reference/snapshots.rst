.. _reference-snapshots:

Snapshots
=========

A snap's system and user data can be excluded from `snapshots
<https://snapcraft.io/docs/snapshots>`_ by specifying exclusion patterns in an optional
metadata file called ``snapshots.yaml``. Such exclusions can be used to control snapshot
content and size.

.. important::

    The ``snap restore`` command replaces a snap's system and user data with the
    snapshot content, meaning that excluded files and directories will be lost.


``snapshots.yaml`` syntax
-------------------------

The ``snapshots.yaml`` configuration file starts with the ``exclude`` keyword followed
by a list of shell-style wildcard patterns to indicate which files or directories to
exclude.

These wildcard patterns must start with a system or user data :ref:`environment variable
<reference-part-environment-variables>`. Only the any wildcard (*) is supported.

.. code-block:: yaml
    :caption: snapshots.yaml

    exclude:
      - <environment-variable>/<path>
      ...
      - <environment-variable>/<path>


Including ``snapshots.yaml`` in a snap
--------------------------------------

The ``snapshots.yaml`` file must be located within a snap's ``meta`` directory. This is
typically done by creating a part that uses either the :ref:`craft_parts_dump_plugin` or
a :ref:`build step override <how-to-override-the-default-build>` to copy
``snapshots.yaml`` from another directory.
