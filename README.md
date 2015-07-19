# goscanssl
Golang application to display SSL connection options and SSL Certificate details

## Installing

Simply use go get to download the code:

    $ go get github.com/gombadi/goscanssl

## To Do List

This repo is still under development and the following are the proprosed improvements.

- make protocol checks run in goroutines for faster output
- support display of connection infor, cert info or both outputs
- better error checking. If one connection refused, no such host etc then stop
- add -e to display cert expire only and a months, days, hours till expired line




