# sftpserver
SFTP server based on libssh library using pthreads.<br/>
To build you may need to set the following cmake variables:-<br/>
CMAKE_INCLUDE_PATH for libssh<br/>
CMAKE_LIBRARY_PATH for libssh<br/>
CMAKE_C_FLAGS="-DSSH_KEYS_DIR=/etc/ssh -DHOME_DIR=/home/user"<br/>