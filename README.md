# Netflix Plugin Beta 0.14.0 for Kodi 18 (plugin.video.netflix)
This only a fork of https://github.com/jakermx/plugin.video.netflix btw https://github.com/caphm/plugin.video.netflix

## Disclaimer

This plugin is not officially commisioned/supported by Netflix.
The trademark "Netflix" is registered by "Netflix, Inc."

## Prerequisites

- Kodi 18 [nightlybuild](http://mirrors.kodi.tv/nightlies/)
- Inputstream.adaptive [>=v2.0.0](https://github.com/peak3d/inputstream.adaptive)
  (must be separately installed from the Kodi repo since Leia Beta 5)
- Cryptdome python library (for Linux systems, install using `pip install --user pycryptodomex` as the user that will run Kodi)

For non-Android devices, the required Widevine DRM binaries will automatically be installed by inputstream.helper.
Please make sure to read the licence agreement that is presented upon Widevine installation, so you know what you´re getting yourself into.

## What is working

- play Videos
- export to library (there is a issue with the api, i get sometimes a api error. But the export was sucessful.)
- select audio streams and subtitle


# Code of Conduct

[Contributor Code of Conduct](Code_of_Conduct.md)
By participating in this project you agree to abide by its terms.

## Licence

Licenced under The MIT License.
