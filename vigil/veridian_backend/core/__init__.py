"""
Core NTFS parsing and volume access primitives for VERIDIAN.

These modules provide low-level abstractions over Windows NTFS structures
($MFT, $USN Journal, $LogFile) and raw volume access. Higher-level
modules should depend on these interfaces rather than touching disk
structures directly.
"""

