# TODO

TODO items or possibile optimization envisaged in this project.

## Non-blocking sockets

We are using blocking socket with `send` and `recv`. It would be
really nice to use non-blocking pattern with `select` and `poll`
instead.

Not already implemented because: considered premature optimization, we
are not going to need it given the amount of data processed and the
utilization count.

## Use IDSESSION/END and pool connections

Especially in the TCP case, opening a connection is costly.

Now we are opening a new connection for each command.  We could use
the IDSESSION and END commands (see man clamd(8)) to establish stable
connections on which to run file scans.  Those connections should be
pooled and kept alive by sending PINGs, as advised in the man clamd(8).

Not already implemented because: considered premature optimization, we
are not going to need it given the amount of data processed and the
utilization count.  Moreover, scanning is already very quick!

## File upload tempfile when using local socket

When we get an uploaded file, we send an open stream to the clamd
instance, avoiding loading the file in memory.  
This seems right, but the reality is somewhat different: the open
stream is NOT read directly from the request.  Instead, flask
(werkzeug) first saves the whole file in a non-named tempfile (if it
is >500k, else it keeps it
in memory).  
So: the stream we are sending is from a file that is already on the
filesystem, and if we are using the unix local socket, we could just
pass the filename to the clamd daemon (SCAN command, not INSTREAM).
this whould be an optimization because we don't have to transfer the
whole file over the socket, we could just let clamd read it.

Not already implemented because: 
* The tempfile is created by Flask (werkzeug) with
`tempfile.SpooledTemporaryFile` (or `tempfile.TemporaryFile`): both
are unnamed and it seems that we cannot get back the filename. We
should probably override the form parser in werkzeug, for example
using `tempfile.NamedTemporaryFile`, but given this is Flask core
behaviour it does not seem right.
* Different behaviour between local socket and TCP socket (we
  obviously cannot send file path to other host)
* Premature optimization: scanning is real fast right now

## Reaching clamd StreamMaxLength

When we reach the StreamMaxLength (property in `clamd.conf`, see man
clamd.conf(5)), clamd should reply with "INSTREAM size limit
exceeded".  What actually happens, though, is that we get a broken
pipe. 

This case is pretty common and has to be handled!
