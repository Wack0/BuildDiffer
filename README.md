# BuildDiff
Does a simple recursive binary diff of two directories. Currently supports PE, NE, LE and LX executables.

Windows servicing/Windows Update packages have special support; version numbers and package hashes in directory names are ignored when comparing two extracted Windows Update packages, allowing for comparing cumulative Windows Updates easily.

Intended to easily obtain a list of what executables have changed between two builds of the same software for later bindiffing.

Usage: `builddiff path\to\build1 path\to\build2`

For each file in the first folder, recursively:
- If it doesn't exist in the second folder, do nothing.
- If the file is not a supported executable, do nothing.
- If the file in the second folder is not in the same executable format, do nothing.
- Compare all text/rodata/data sections of both executables (ignore `.rsrc`; zero out `IMAGE_EXPORT_DIRECTORY.TimeDateStamp` and all `IMAGE_DEBUG_DIRECTORY` blocks in PE; for PE files with bound imports, the IAT is also zeroed). If they are equal, do nothing.
- Print the executable type, the filename, the section categories that are different, and a list of section numbers with differences.

For section categories: `text` means text/code, `rdata` means read-only data, `data` means read-write data, `sections` means section count changed, or section flags changed.

If all sections of an executable are different, then `all` is printed instead of a list of section numbers.
