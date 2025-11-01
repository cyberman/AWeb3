# AWeb 3

This is AWeb 3 APL open source version, an HTML 3 web browser for Amiga.

## [amigazen project](http://www.amigazen.com)

*A web, suddenly*

*Forty years meditation*

*Minds awaken, free*

**amigazen project** uses modern software development tools and methods to update and rerelease classic Amiga open source software. Projects include a new AWeb, a new Amiga Python 2, and the ToolKit project - a universal SDK for Amiga.

Key to the amigazen project approach is ensuring every project can be built with the same common set of development tools and configurations, so the ToolKit project was created to provide a standard configuration for Amiga development. All *amigazen project* releases will be guaranteed to build against the ToolKit standard so that anyone can download and begin contributing straightaway without having to tailor the toolchain for their own setup.

The original authors of the *AWeb* software are not affiliated with the amigazen project. This software is redistributed on terms described in the documentation, particularly the file LICENSE or LICENSE.md

The amigazen project philosophy philosophy is based on openness:

*Open* to anyone and everyone	- *Open* source and free for all	- *Open* your mind and create!

PRs for all projects are gratefully received at [GitHub](https://github.com/amigazen/). While the focus now is on classic 68k software, it is intended that all amigazen project releases can be ported to other Amiga-like systems including AROS and MorphOS where feasible.

## About AWeb 3

AWeb is one of the most sophisticated web browsers (for its time) ever released on the Amiga platform. The original author, Yvon Rozijn, kindly made AWeb open source under the AWeb Public License. 

This project's first aim is to update the code so it builds against the NDK3.2, which largely means replacing the ClassAct UI APIs with the equivalent ReAction versions, as well as updating the networking code to work properly with RoadShow and the latest AmiSSL, and ensuring it can be built easily out of the box against the ToolKit standard by anyone with an Amiga computer.

## Roadmap

The first AWeb APL open source release was version 3.4, in 2003 from the _AWeb Open Source Development Team_.

Since then one further "3.5" beta release was made for both OS4 and classic Amiga, however the source code to the 68k release of 3.5 seem to no longer be available to the public, if it ever was. The OS4 version is available on os4depot. This release incorporated many improvements to JavaScript, image rendering and much more, that are certainly worth keeping.

Thus, this version 3.6 is derived directly from the 3.4 source code release. 

The roadmap for AWeb 3 under amigazen project is, for now:

### AWeb 3.6

- Stable re-release of AWeb 3.4 functionality built against ReAction, Roadshow (with INet225 support disabled), P96 (replacing no longer supported Cybergraphics libraries), AmiSSL 5 and NDK3.2
- Cherry pick of the most important patches from the various 3.5 releases found in the wild, where code is available
- Add GZip compression support
- Update to AmiSSL 5.20
- Refresh icons
- Change inconsistent names AWeb-II, AWeb3: and AWebPath: to simply "AWeb"

### AWeb 3.7

- Update image libraries to newer versions for JPEG, PNG and GIF
- Explore adding plugin support for WebP
- Cherry pick OS4 native build patches and other enhancements from 3.5 release

### Future releases

- Wait and see! 

## About ToolKit

**ToolKit** exists to solve the problem that most Amiga software was written in the 1980s and 90s, by individuals working alone, each with their own preferred setup for where their dev tools are run from, where their include files, static libs and other toolchain artifacts could be found, which versions they used and which custom modifications they made. Open source collaboration did not exist as we know it in 2025. 

**ToolKit** from amigazen project is a work in progress to make a standardised installation of not just the Native Developer Kit, but the compilers, build tools and third party components needed to be able to consistently build projects in collaboration with others, without each contributor having to change build files to work with their particular toolchain configuration. 

All *amigazen project* releases will release in a ready to build configuration according to the ToolKit standard.

Each component of **ToolKit** is open source and will have it's own github repo, while ToolKit itself will eventually be released as an easy to install package containing the redistributable components, as well as scripts to easily install the parts that are not freely redistributable from archive.

## Contact 

- At GitHub https://github.com/amigazen/aweb3/ 
- on the web at http://www.amigazen.com/aweb/ (Amiga browser compatible)
- or email aweb@amigazen.com

## Acknowledgements

*Amiga* is a trademark of **Amiga Inc**. 

Original AWeb by Yvon Rozijn, released as AWeb APL to the open source community