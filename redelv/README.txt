WHAT IS redelv?

The program 'redelv' is a third-party role playing game scenario editor system
interoperable with the Delver Engine by Glenn Andreas. Besides modifying the 
scenario file of a Delver-based game (e.g. "Cythera Data"), it can create and 
apply patches and perform other manipulations of Delver Archives.

redelv is based on the python module delv, which was itself prepared based on
the DelvTechWiki's technical documentation project, which can be found here:
http://www.ferazelhosting.net/wiki/

REQUIREMENTS / PYTHON VERSION

redelv runs on Python 3 with PyGObject and GTK 3. The port from Python 2 and
PyGTK is the work of Chaim Leib Halbert, on the gtk3-auto branch of
github.com/chaimleib/delvmod, and is the only one there is; it was merged here
with its history, so the commits carry their own authorship. On macOS it wants
'brew install gtk+3 pygobject3', and 'pip install parsley' for the assembler.

The port is not finished. It opens an archive, draws the resource tree and
offers New, Open, Close, Underlay Scenario, About and Quit. Upstream's Save,
Import, Export, Edit and Patch menus have no GTK 3 counterpart yet, and no
editor can be opened at all: the call in row_activated that opened one is
commented out, and menu_resource_editor was not ported. The editor modules
themselves are converted, but nothing reaches them.

Until that is finished, editing a resource, assembling a script and making a
patch are all available without the GUI: see examples/rdasm.py, which assembles
.rdasm source, and examples/mag.py, which diffs two archives into a Delver
patch and applies patches to an archive.

The underlying delv module runs on Python 3 and on Apple Silicon whether the
GUI does or not.

INSTALLING
pip install .

HOW TO USE IT
Run the command 'redelv' from your command line after installing.
It's a GUI program, so you just mess with it until you figure it out. 
Make backups.

The suggested workflow is to use redelv on a copy of "Cythera Data" that is
on a virtual disk shared with a Mac Emulator (e.g. BasiliskII or SheepShaver).
After making your desired mods, you can use redelv to make a patch that will
modify an unmodified copy of "Cythera Data" to match your modified one.



LICENSE
Free software under the GPL3. (As required by using delv, which is GPL3,
not LGPL3.) The developers of delv politely ask you not to use delv to create
versions of the "Cythera Data" file modified to bypass the shareware 
restrictions, a request that also applies to redelv.





