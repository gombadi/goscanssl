# goscanssl
Golang application to display SSL connection options and SSL Certificate details

## Installing

Simply use go get to download the code:

    $ go get github.com/gombadi/goscanssl

## Usage

    $ goscanssl -h www.example.com

```
Usage of goscanssl:
  -a    Display all Info
  -cert
        Display Certificate Info
  -conn
        Display Connection Info
  -h string
        Remote host to test
  -p string
        Port to connect to. Default port: 443 (default "443")
  -v    Display verbose output
```


## To Do List

This repo is still under development and the following are the proprosed improvements but more are to come.

- better error checking. If one connection refused, no such host etc then stop
- add -e to display cert expire only and a months, days, hours till expired line




