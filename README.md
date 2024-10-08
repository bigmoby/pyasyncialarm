# pyasyncialarm
Python library to interface with [iAlarm systems](https://www.antifurtocasa365.it/).

It has also been confirmed to work with the alarm systems brands Meian and Emooluxr.

From the version 1.0 this library switched from webscraping the local configuration webpage to using the API that Android and iOS app use.
Thanks to https://github.com/wildstray/meian-client for writing down the API specs.


## Development

Please run before creating a PR:

`pre-commit run --all-files`

and

`pytest -vv tests/test_pyasyncialarm.py`
