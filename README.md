# safe_ftp

based on beckysag/ftp.

FTP Client-Server Implementation
===========

Simple implementation of a file transfer program. It includes custom client and server programs that provide functionality to authenticate a user, list remote files, and retrieve remote files.

### Directory Layout

client:

```txt
  ftclient
  users/    (private key)
    AverageSoul
    juicymio
    xxx
    ...
  server/  (server public key)
    server.pub
  files    (downloaded files)
```

server:

```txt
  ftserver
  uploads/  (uploaded files)
    ...
  users/    (public key)
    AverageSoul.pub
    juicymio.pub
    xxx.pub
    ...
    server_private_key

```

```

### Usage

build crypto_utils first

```

 cd crypto_utils
 make

```

To compile and link ftserve:

```

 cd ftp/server/
 make

```

To compile and link ftclient:

```

 cd ftp/client/
 make

```

To run ftserve:

```

 server/ftserve PORTNO

```

To run ftclient:

```

 $ client/ftclient HOSTNAME PORTNO

 Commands:
  list
  put <filename>
  get <filename>
  quit

```

Available commands:

```

list            - retrieve list of files in the current remote directory
get <filename>  - get the specified file
put <filename>  - put the specified file
quit            - end the ftp session

```
