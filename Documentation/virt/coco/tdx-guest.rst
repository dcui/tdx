.. SPDX-License-Identifier: GPL-2.0

===================================================================
TDX Guest API Documentation
===================================================================

1. General description
======================

The TDX guest driver exposes IOCTL interfaces via /dev/tdx-guest misc
device to allow userspace to get certain TDX guest specific details.

2. API description
==================

In this section, for each supported IOCTL, following information is
provided along with a generic description.

:Input parameters: Parameters passed to the IOCTL and related details.
:Output: Details about output data and return value (with details about the non
         common error values).

2.1 TDX_CMD_GET_REPORT
----------------------

:Input parameters: struct tdx_report_req
:Output: Upon successful execution, TDREPORT data is copied to
         tdx_report_req.tdreport and return 0. Return -EINVAL for
         invalid operands, -EIO on TDCALL failure or standard error
         number on other common failures.

The TDX_CMD_GET_REPORT IOCTL can be used by the attestation software to
get the TDREPORT from the TDX module using TDCALL[TDG.MR.REPORT].

Reference
---------

TDX reference material is collected here:

https://www.intel.com/content/www/us/en/developer/article...

The driver is based on TDX module specification v1.0 and TDX GHCI specification v1.0.
