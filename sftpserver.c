/****************************************************************************
 * MIT License
 *
 * Copyright (c) 2020 Steve Pickford
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 ****************************************************************************/

/**
 * @file sftpserver.c
 * @author Steve Pickford
 * @date 5 Dec 2020
 * @brief SFTP server based on libssh and pthreads.
 *
Typo * @see https://github.com/sjp27/sftpserver
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdio.h>
#include <dirent.h>
#ifdef WIN32
/*#define WIN32_CHECK_FOR_MEMORY_LEAKS*/
#include <direct.h>
#endif
#include <semaphore.h>
#include <errno.h>
#ifdef WIN32
#include <sys/utime.h>
#else
#include <utime.h>
#endif
#include <signal.h>

#include <libssh/libssh.h>
#include <libssh/server.h>
#define WITH_SERVER 1 /**< Compile with SFTP server support */
#include <libssh/sftp.h>
#include <libssh/callbacks.h>


#define STR(s) XSTR(s) /**< Stringification support */
#define XSTR(s) #s /**< Stringification support*/

#ifndef SSH_KEYS_DIR
#define SSH_KEYS_DIR /etc/ssh /**< SSH keys directory */
#endif

#ifndef HOME_DIR
#define HOME_DIR /home/user /**< Home directory */
#endif

#define BINDPORT "2222" /**< Port to bind to */
#define MAX_HANDLES 20 /**< Maximum handles */
#define NUM_ENTRIES_PER_PACKET 50 /**< Maximum entries per packet for readdir */
#define MAX_LONG_NAME_LEN (NAME_MAX + 100) /**< Maximum long name length for readdir */
#define MAX_THREADS 10 /**< Maximum number of threads */

/**
 * @brief Handle type enum
 */
enum
{
    DIR_HANDLE,
    FILE_HANDLE
};

/**
 * @brief Handle table entry
 */
struct handle_table_entry
{
    int type;         /**< Handle type */
    void* handle;     /**< Handle */
    void* session_id; /**< Session ID */
    char* path;       /**< Path */
};

/**
 * @brief Handle table semaphore
 */
static sem_t s_handle_table_mutex;

/**
 * @brief Handle table
 */
static struct handle_table_entry s_handle_table[MAX_HANDLES];

/**
 * @brief Initialise handle table
 */
static void init_handle_table(void)
{
    sem_init(&s_handle_table_mutex, 0, 1);

    for(int i = 0; i < MAX_HANDLES; i++)
    {
        s_handle_table[i].type = DIR_HANDLE;
        s_handle_table[i].handle = NULL;
        s_handle_table[i].session_id = NULL;
        s_handle_table[i].path = NULL;
    }
}

/**
 * @brief Add handle to table
 * @param z_type Handle type
 * @param z_handle Handle
 * @param z_path Path
 * @param z_session_id Session ID
 * @return SSH_OK or SSH_ERROR
 */
static int add_handle(int z_type, void* z_handle, const char* z_path, void* z_session_id)
{
    int ret = SSH_ERROR;

    if(z_handle != NULL)
    {
        sem_wait(&s_handle_table_mutex);

        for (int i = 0; i < MAX_HANDLES; i++)
        {
            if (s_handle_table[i].handle == NULL)
            {
                s_handle_table[i].type = z_type;
                s_handle_table[i].handle = z_handle;
                s_handle_table[i].path = (char *)malloc ((strlen(z_path) + 1) * sizeof(char));
                strcpy(s_handle_table[i].path, z_path);
                s_handle_table[i].session_id = z_session_id;
                ret = SSH_OK;
                break;
            }
        }

        sem_post(&s_handle_table_mutex);
    }

    return(ret);
}

/**
 * @brief Get handle path from table
 * @param z_handle Handle
 * @return handle path
 */
static char* get_handle_path(void* z_handle)
{
    char* ret = NULL;

    if(z_handle != NULL)
    {
        sem_wait(&s_handle_table_mutex);

        for (int i = 0; i < MAX_HANDLES; i++)
        {
            if (s_handle_table[i].handle == z_handle)
            {
                ret = s_handle_table[i].path;
                break;
            }
        }

        sem_post(&s_handle_table_mutex);
    }

    return(ret);
}

/**
 * @brief Close handle in table
 * @param z_handle Handle
 * @return SSH_OK or SSH_ERROR
 */
static int close_handle(void* z_handle)
{
    int ret = SSH_ERROR;

    if(z_handle != NULL)
    {
        sem_wait(&s_handle_table_mutex);

        for (int i = 0; i < MAX_HANDLES; i++)
        {
            if (s_handle_table[i].handle == z_handle)
            {
                /* Close handle */
                switch(s_handle_table[i].type)
                {
                    case DIR_HANDLE:
                    {
                        closedir((DIR *)z_handle);
                        break;
                    }

                    case FILE_HANDLE:
                    {
                        fclose((FILE *)z_handle);
                        break;
                    }
                }

                /* Remove handle from table */
                s_handle_table[i].handle = NULL;
                s_handle_table[i].session_id = NULL;
                if(s_handle_table[i].path != NULL)
                {
                    free(s_handle_table[i].path);
                    s_handle_table[i].path = NULL;
                }
                ret = SSH_OK;
                break;
            }
        }

        sem_post(&s_handle_table_mutex);
    }

    return(ret);
}

/**
 * @brief Free handles in table for given session
 * @param z_session_id Session ID
 */
static void free_handles(void* z_session_id)
{
    if(z_session_id != NULL)
    {
        sem_wait(&s_handle_table_mutex);

        for (int i = 0; i < MAX_HANDLES; i++)
        {
            if (s_handle_table[i].session_id == z_session_id)
            {
                /* Close handle */
                switch(s_handle_table[i].type)
                {
                    case DIR_HANDLE:
                    {
                        closedir((DIR *)s_handle_table[i].handle);
                        break;
                    }

                    case FILE_HANDLE:
                    {
                        fclose((FILE *)s_handle_table[i].handle);
                        break;
                    }
                }

                s_handle_table[i].handle = NULL;
                s_handle_table[i].session_id = NULL;
                if(s_handle_table[i].path != NULL)
                {
                    free(s_handle_table[i].path);
                    s_handle_table[i].path = NULL;
                }
            }
        }

        sem_post(&s_handle_table_mutex);
    }
}

/**
 * @brief unix errno to SSH status
 * @param z_errno Error number
 * @return SSH status
 */
static int unix_errno_to_ssh_status(int z_errno)
{
    int ret = SSH_FX_OK;

    switch (z_errno)
    {
        case 0:
        {
            ret = SSH_FX_OK;
            break;
        }
        case ENOENT:
        case ENOTDIR:
        case EBADF:
        case ELOOP:
        {
            ret = SSH_FX_NO_SUCH_FILE;
            break;
        }
        case EPERM:
        case EACCES:
        case EFAULT:
        {
            ret = SSH_FX_PERMISSION_DENIED;
            break;
        }
        case ENAMETOOLONG:
        case EINVAL:
        {
            ret = SSH_FX_BAD_MESSAGE;
            break;
        }
        case ENOSYS:
        {
            ret = SSH_FX_OP_UNSUPPORTED;
            break;
        }
        default:
        {
            ret = SSH_FX_FAILURE;
            break;
        }
    }

    return ret;
}

/**
 * @brief Clear filexfer attrib
 * @param z_attr Pointer to attributes struct
 */
static void clear_filexfer_attrib(struct sftp_attributes_struct* z_attr)
{
    z_attr->flags = 0;
    z_attr->size = 0;
    z_attr->uid = 0;
    z_attr->gid = 0;
    z_attr->permissions = 0;
    z_attr->atime = 0;
    z_attr->mtime = 0;
}

/**
 * @brief stat to filexfer attrib
 * @param z_st Pointer to stat struct
 * @param z_attr Pointer to attributes struct
 */
#ifdef WIN32
static void stat_to_filexfer_attrib(const struct _stat* z_st, struct sftp_attributes_struct* z_attr)
#else
static void stat_to_filexfer_attrib(const struct stat* z_st, struct sftp_attributes_struct* z_attr)
#endif
{
    z_attr->flags = 0;
    z_attr->flags |= (uint32_t)SSH_FILEXFER_ATTR_SIZE;
    z_attr->size = z_st->st_size;
    z_attr->flags |= (uint32_t)SSH_FILEXFER_ATTR_UIDGID;
    z_attr->uid = z_st->st_uid;
    z_attr->gid = z_st->st_gid;
    z_attr->flags |= (uint32_t)SSH_FILEXFER_ATTR_PERMISSIONS;
    z_attr->permissions = z_st->st_mode;
    z_attr->flags |= (uint32_t)SSH_FILEXFER_ATTR_ACMODTIME;
    z_attr->atime = z_st->st_atime;
    z_attr->mtime = z_st->st_mtime;
}

/**
 * @brief readdir long name
 * @param z_file_name Pointer to file_name
 * @param z_st Pointer to stat structure
 * @param z_long_name Pointer to long_name
 * @return Pointer to long_name
 */
#ifdef WIN32
char* readdir_long_name(char* z_file_name, struct _stat* z_st, char* z_long_name)
#else
char* readdir_long_name(char* z_file_name, struct stat* z_st, char* z_long_name)
#endif
{
    char tmpbuf[MAX_LONG_NAME_LEN];
    char time[50];
    char* ptr = z_long_name;
    int mode = z_st->st_mode;

    *ptr = '\0';

    switch(mode & S_IFMT)
    {
        case S_IFDIR:
        {
            *ptr++ = 'd';
            break;
        }
        default:
        {
            *ptr++ = '-';
            break;
        }
    }
    /* user */
    if(mode & 0400)
    {
        *ptr++ = 'r';
    }
    else
    {
        *ptr++ ='-';
    }
    if(mode & 0200)
    {
        *ptr++ = 'w';
    }
    else
    {
        *ptr++ = '-';
    }
    if(mode & 0100)
    {
#ifdef WIN32
        *ptr++ = '-';
#else
        if(mode & S_ISUID)
        {
            *ptr++ = 's';
        }
        else
        {
            *ptr++ = 'x';
        }
#endif
    }
    else
    {
        *ptr++ = '-';
    }
    /* group */
    if(mode & 040)
    {
        *ptr++ = 'r';
    }
    else
    {
        *ptr++ = '-';
    }
    if(mode & 020)
    {
        *ptr++ = 'w';
    }
    else
    {
        *ptr++ ='-';
    }
    if(mode & 010)
    {
        *ptr++ = 'x';
    }
    else
    {
        *ptr++ = '-';
    }
    /* other */
    if(mode & 04)
    {
        *ptr++ = 'r';
    }
    else
    {
        *ptr++ = '-';
    }
    if(mode & 02)
    {
        *ptr++ = 'w';
    }
    else
    {
        *ptr++ = '-';
    }
    if(mode & 01)
    {
        *ptr++ = 'x';
    }
    else
    {
        *ptr++ = '-';
    }
    *ptr++ = ' ';
    *ptr = '\0';

    snprintf(tmpbuf, sizeof(tmpbuf),"%3d %d %d %d", (int)z_st->st_nlink,
             (int)z_st->st_uid, (int)z_st->st_gid, (int)z_st->st_size);
    strcat(z_long_name, tmpbuf);

#ifdef WIN32
    ctime_s(time, sizeof(time), &z_st->st_mtime);
#else
    ctime_r(&z_st->st_mtime, time);
#endif

    if(ptr = strchr(time,'\n'))
    {
        *ptr = '\0';
    }
    snprintf(tmpbuf,sizeof(tmpbuf)," %s %s", time + 4, z_file_name);
    strcat(z_long_name, tmpbuf);

    return z_long_name;
}

/**
 * @brief Check password
 * @param z_user User
 * @param z_password Password
 * @return SSH_OK or SSH_ERROR
 */
static int check_password(const char* z_user, const char* z_password)
{
    int check = SSH_OK;

    if(strcmp(z_user,"user") != 0)
    {
        check = SSH_ERROR;
    }
    if(strcmp(z_password,"pass") != 0)
    {
        check = SSH_ERROR;
    }
    return check;
}

/**
 * @brief Authenticate session
 * @param z_session Pointer to ssh session
 * @return SSH_OK or SSH_ERROR
 */
static int authenticate(ssh_session z_session)
{
    int auth = SSH_ERROR;
    ssh_message message = NULL;

    do
    {
        message=ssh_message_get(z_session);
        if(message == NULL)
        {
            break;
        }
        switch(ssh_message_type(message))
        {
            case SSH_REQUEST_AUTH:
            {
                switch (ssh_message_subtype(message))
                {
                    case SSH_AUTH_METHOD_PASSWORD:
                    {
                        auth = check_password(ssh_message_auth_user(message), ssh_message_auth_password(message));

                        if(auth == SSH_OK)
                        {
                            ssh_message_auth_reply_success(message, 0);
                            break;
                        }
                        else
                        {
                            ssh_message_reply_default(message);
                        }
                        break;
                    }

                    case SSH_AUTH_METHOD_NONE:
                    default:
                    {
                        ssh_message_auth_set_methods(message, SSH_AUTH_METHOD_PASSWORD);
                        ssh_message_reply_default(message);
                        break;
                    }
                }
                break;
            }
            default:
            {
                ssh_message_reply_default(message);
                break;
            }
        }
        ssh_message_free(message);
    } while (auth == SSH_ERROR);

    return(auth);
}

/**
 * @brief Open channel
 * @param z_session Pointer to ssh session
 * @return ssh channel
 */
static ssh_channel open_channel(ssh_session z_session)
{
    ssh_channel chan = NULL;
    ssh_message message = NULL;

    do
    {
        message=ssh_message_get(z_session);

        if(message != NULL)
        {
            switch(ssh_message_type(message))
            {
                case SSH_REQUEST_CHANNEL_OPEN:
                {
                    if (ssh_message_subtype(message) == SSH_CHANNEL_SESSION)
                    {
                        chan = ssh_message_channel_request_open_reply_accept(message);
                        break;
                    }
                }
                default:
                {
                    ssh_message_reply_default(message);
                    break;
                }
            }
            ssh_message_free(message);
        }
    } while((message != NULL) && (chan == NULL));

    return(chan);
}

/**
 * @brief SFTP subsystem request
 * @param z_session Pointer to ssh session
 * @return SSH_OK or SSH_ERROR
 */
static int sftp_subsystem_request(ssh_session z_session)
{
    int ret = SSH_ERROR;
    ssh_message message = NULL;

    do
    {
        message=ssh_message_get(z_session);

        if((message != NULL) && (ssh_message_type(message)==SSH_REQUEST_CHANNEL))
        {
            int sub_type = ssh_message_subtype(message);

            if(sub_type == SSH_CHANNEL_REQUEST_SUBSYSTEM)
            {
                const char *subsystem = ssh_message_channel_request_subsystem(message);

                if(strcmp(subsystem, "sftp") == 0)
                {
                    ret = SSH_OK;
                    ssh_message_channel_request_reply_success(message);
                }
            }
        }

        ssh_message_free(message);

    } while (message && (ret == SSH_ERROR));

    return(ret);
}

/**
 * @brief Process close command
 * @param z_client_message Pointer to client message
 * @return SSH_OK or SSH_ERROR
 */
static int process_close(sftp_client_message z_client_message)
{
    int ret = SSH_OK;
    void* handle = (DIR*)sftp_handle(z_client_message->sftp, z_client_message->handle);

    ret = close_handle(handle);

    if(ret == SSH_OK)
    {
        sftp_reply_status(z_client_message, SSH_FX_OK, NULL);
    }
    else
    {
        sftp_reply_status(z_client_message, SSH_FX_BAD_MESSAGE, "Invalid handle");
    }

    return(ret);
}

/**
 * @brief Process fstat command
 * @param z_client_message Pointer to client message
 * @return SSH_OK or SSH_ERROR
 */
static int process_fstat(sftp_client_message z_client_message)
{
    int ret = SSH_OK;
    FILE* fp = (FILE*)sftp_handle(z_client_message->sftp, z_client_message->handle);
    int fd = fileno(fp);
    struct sftp_attributes_struct attr;
#ifdef WIN32
    struct _stat st;
#else
    struct stat st;
#endif

#ifdef WIN32
    if(_fstat(fd, &st) == 0)
#else
    if(fstat(fd, &st) == 0)
#endif
    {
        stat_to_filexfer_attrib(&st, &attr);
        sftp_reply_attr(z_client_message, &attr);
    }
    else
    {
        int status = unix_errno_to_ssh_status(errno);
        sftp_reply_status(z_client_message, status, NULL);
        ret = SSH_ERROR;
    }

    return(ret);
}

/**
 * @brief Process lstat command
 * @param z_client_message Pointer to client message
 * @return SSH_OK or SSH_ERROR
 */
static int process_lstat(sftp_client_message z_client_message)
{
    int ret = SSH_OK;
    const char* file_name = sftp_client_message_get_filename(z_client_message);
    struct sftp_attributes_struct attr;
#ifdef WIN32
    struct _stat st;
#else
    struct stat st;
#endif

#ifdef WIN32
    if(_stat(file_name, &st) == 0)
#else
    if(lstat(file_name, &st) == 0)
#endif
    {
        stat_to_filexfer_attrib(&st, &attr);
        sftp_reply_attr(z_client_message, &attr);
    }
    else
    {
        int status = unix_errno_to_ssh_status(errno);
        sftp_reply_status(z_client_message, status, NULL);
        ret = SSH_ERROR;
    }

    return(ret);
}

/**
 * @brief Process mkdir command
 * @param z_client_message Pointer to client message
 * @return SSH_OK or SSH_ERROR
 */
static int process_mkdir(sftp_client_message z_client_message)
{
    int ret = SSH_OK;
    int status = SSH_FX_OK;
    const char* dir_name = sftp_client_message_get_filename(z_client_message);
    uint32_t message_flags = z_client_message->flags;
    uint32_t permission = z_client_message->attr->permissions;
    uint32_t mode = (message_flags & (uint32_t)SSH_FILEXFER_ATTR_PERMISSIONS) ? permission & (uint32_t)07777 : 0777;

#ifdef WIN32
    if(_mkdir(dir_name) < 0)
#else
    if(mkdir(dir_name, mode) < 0)
#endif
    {
        status = unix_errno_to_ssh_status(errno);
        ret = SSH_ERROR;
    }

    sftp_reply_status(z_client_message, status, NULL);

    return(ret);
}

/**
 * @brief Process open command
 * @param z_client_message Pointer to client message
 * @return SSH_OK or SSH_ERROR
 */
static int process_open(sftp_client_message z_client_message)
{
    int ret = SSH_ERROR;
    const char* file_name = sftp_client_message_get_filename(z_client_message);
    uint32_t message_flags = z_client_message->flags;
    FILE* fp = NULL;
    char mode[3];

    if(( (message_flags & (uint32_t)SSH_FXF_READ) == SSH_FXF_READ) &&
       ( (message_flags & (uint32_t)SSH_FXF_WRITE) == SSH_FXF_WRITE))
    {
        if((message_flags & (uint32_t)SSH_FXF_CREAT) == SSH_FXF_CREAT)
        {
            strcpy(mode, "w+");
        }
        else
        {
            strcpy(mode, "r+");
        }
    }
    else if((message_flags & (uint32_t)SSH_FXF_READ) == SSH_FXF_READ)
    {
        if((message_flags & (uint32_t)SSH_FXF_APPEND) == SSH_FXF_APPEND)
        {
            strcpy(mode, "a+");
        }
        else
        {
            strcpy(mode, "r");
        }
    }
    else if((message_flags & (uint32_t)SSH_FXF_WRITE) == SSH_FXF_WRITE)
    {
        strcpy(mode, "w");
    }

    fp = fopen(file_name, mode);

    if(fp != NULL)
    {
        if(add_handle(FILE_HANDLE, fp, file_name, z_client_message->sftp) == SSH_OK)
        {
            ssh_string handle = sftp_handle_alloc(z_client_message->sftp, fp);
            sftp_reply_handle(z_client_message, handle);
            ssh_string_free(handle);
            ret = SSH_OK;
        }
        else
        {
            fclose(fp);
            sftp_reply_status(z_client_message, SSH_FX_FAILURE, "No handle available");
        }
    }
    else
    {
        sftp_reply_status(z_client_message, SSH_FX_NO_SUCH_FILE, "No such file");
    }

    return(ret);
}

/**
 * @brief Process opendir command
 * @param z_client_message Pointer to client message
 * @return SSH_OK or SSH_ERROR
 */
static int process_opendir(sftp_client_message z_client_message)
{
    int ret = SSH_ERROR;
    DIR* dir = NULL;
    const char* file_name = sftp_client_message_get_filename(z_client_message);

    dir = opendir(file_name);

    if(dir != NULL)
    {
        if(add_handle(DIR_HANDLE, dir, file_name, z_client_message->sftp) == SSH_OK)
        {
            ssh_string handle = sftp_handle_alloc(z_client_message->sftp, dir);
            sftp_reply_handle(z_client_message, handle);
            ssh_string_free(handle);
            ret = SSH_OK;
        }
        else
        {
            closedir(dir);
            sftp_reply_status(z_client_message, SSH_FX_FAILURE, "No handle available");
        }
    }
    else
    {
        sftp_reply_status(z_client_message, SSH_FX_NO_SUCH_FILE, "No such directory");
    }
    return(ret);
}

/**
 * @brief Process read command
 * @param z_client_message Pointer to client message
 * @return SSH_OK or SSH_ERROR
 */
static int process_read(sftp_client_message z_client_message)
{
    int ret = SSH_ERROR;
    FILE* fp = (FILE*)sftp_handle(z_client_message->sftp, z_client_message->handle);

    if(fp != NULL)
    {

        if(fseek(fp, z_client_message->offset, SEEK_SET) == 0)
        {
            uint32_t n;
            char* buffer = (char *)malloc ((z_client_message->len) * sizeof(char));

            ret = SSH_OK;

            n = fread(buffer, sizeof(char), z_client_message->len, fp);

            if (n > 0)
            {
                sftp_reply_data(z_client_message, buffer, n);
            }
            else
            {
                sftp_reply_status(z_client_message, SSH_FX_EOF, "EOF encountered");
            }

            free(buffer);
        }
        else
        {
            sftp_reply_status(z_client_message, SSH_FX_FAILURE, NULL);
        }
    }
    else
    {
        sftp_reply_status(z_client_message, SSH_FX_INVALID_HANDLE, NULL);
    }

    return(ret);
}

/**
 * @brief Process readdir command
 * @param z_client_message Pointer to client message
 * @return SSH_OK or SSH_ERROR
 */
static int process_readdir(sftp_client_message z_client_message)
{
    int ret = SSH_ERROR;
    int entries = 0;
    struct dirent *dentry;
    DIR* dir = (DIR*)sftp_handle(z_client_message->sftp, z_client_message->handle);

    if(dir != NULL)
    {
        char long_path[PATH_MAX];
        int path_length;

        ret = SSH_OK;
        strcpy(long_path, get_handle_path((void*) dir));
        strcat(long_path, "/");
        path_length = (int)strlen(long_path);

        for (int i = 0; i < NUM_ENTRIES_PER_PACKET; i++)
        {
            dentry = readdir(dir);

            if (dentry != NULL)
            {
                struct sftp_attributes_struct attr;
#ifdef WIN32
                struct _stat st;
#else
                struct stat st;
#endif
                char long_name[MAX_LONG_NAME_LEN];

                strcpy(&long_path[path_length], dentry->d_name);

#ifdef WIN32
                if(_stat(long_path, &st) == 0)
#else
                if(stat(long_path, &st) == 0)
#endif
                {
                    stat_to_filexfer_attrib(&st, &attr);
                }
                else
                {
                    clear_filexfer_attrib(&attr);
                }

                sftp_reply_names_add(z_client_message, dentry->d_name, readdir_long_name(dentry->d_name, &st, long_name), &attr);
                entries++;
            }
            else
            {
                break;
            }
        }

        if(entries > 0)
        {
            ret = sftp_reply_names(z_client_message);
        }
        else
        {
            sftp_reply_status(z_client_message, SSH_FX_EOF, NULL);
        }
    }
    else
    {
        sftp_reply_status(z_client_message, SSH_FX_INVALID_HANDLE, NULL);
    }

    return(ret);
}

/**
 * @brief Process realpath command
 * @param z_client_message Pointer to client message
 * @return SSH_OK or SSH_ERROR
 */
static int process_realpath(sftp_client_message z_client_message)
{
    int ret = SSH_ERROR;
    int status = SSH_FX_FAILURE;
    const char* path = sftp_client_message_get_filename(z_client_message);

    if(path != NULL)
    {
        char long_path[PATH_MAX];

#ifdef WIN32
        if (_fullpath(long_path, path, PATH_MAX) != NULL)       
#else
        if (realpath(path, long_path) != NULL)
#endif
        {
            sftp_reply_name(z_client_message, long_path, NULL);
            ret = SSH_OK;
        }
        else
        {
            status = unix_errno_to_ssh_status(errno);
        }
    }

    if(ret == SSH_ERROR)
    {
        sftp_reply_status(z_client_message, status, NULL);
    }

    return(ret);
}

/**
 * @brief Process remove command
 * @param z_client_message Pointer to client message
 * @return SSH_OK or SSH_ERROR
 */
static int process_remove(sftp_client_message z_client_message)
{
    int ret = SSH_OK;
    int status = SSH_FX_OK;
    const char* file_name = sftp_client_message_get_filename(z_client_message);

    if(unlink(file_name) < 0)
    {
        ret = SSH_ERROR;
        status = unix_errno_to_ssh_status(errno);
    }

    sftp_reply_status(z_client_message, status, NULL);

    return(ret);
}

/**
 * @brief Process rename command
 * @param z_client_message Pointer to client message
 * @return SSH_OK or SSH_ERROR
 */
static int process_rename(sftp_client_message z_client_message)
{
    int ret = SSH_ERROR;
    int status = SSH_FX_FAILURE;
    const char* old_file_name = sftp_client_message_get_filename(z_client_message);
    const char* new_file_name = sftp_client_message_get_data(z_client_message);
#ifdef WIN32
    struct _stat st;
#else
    struct stat st;
#endif

    /* Check old file name exists */
#ifdef WIN32
    if(_stat(old_file_name, &st) == 0)
#else
    if(lstat(old_file_name, &st) == 0)
#endif
    {
        /* Check new file name does not already exist */
#ifdef WIN32
        if(_stat(new_file_name, &st) == -1)
#else
        if(stat(new_file_name, &st) == -1)
#endif
        {
            if(rename(old_file_name, new_file_name) == 0)
            {
                ret = SSH_OK;
                status = SSH_FX_OK;
            }
            else
            {
                status = unix_errno_to_ssh_status(errno);
            }
        }
    }
    else
    {
        status = unix_errno_to_ssh_status(errno);
    }

    sftp_reply_status(z_client_message, status, NULL);

    return(ret);
}

/**
 * @brief Process rmdir command
 * @param z_client_message Pointer to client message
 * @return SSH_OK or SSH_ERROR
 */
static int process_rmdir(sftp_client_message z_client_message)
{
    int ret = SSH_OK;
    int status = SSH_FX_OK;
    const char* dir_name = sftp_client_message_get_filename(z_client_message);

    if(rmdir(dir_name) < 0)
    {
        ret = SSH_ERROR;
        status = unix_errno_to_ssh_status(errno);
    }

    sftp_reply_status(z_client_message, status, NULL);

    return(ret);
}

/**
 * @brief Process setstat command
 * @param z_client_message Pointer to client message
 * @return SSH_OK or SSH_ERROR
 */
static int process_setstat(sftp_client_message z_client_message)
{
    int ret = SSH_OK;
    int status = SSH_FX_OK;
    const char* file_name = NULL;

    if(sftp_client_message_get_type(z_client_message) == SSH_FXP_FSETSTAT)
    {
        FILE* fp = (FILE*)sftp_handle(z_client_message->sftp, z_client_message->handle);
        file_name = get_handle_path(fp);
    }
    else
    {
        file_name = sftp_client_message_get_filename(z_client_message);
    }

    if(z_client_message->attr->flags & (uint32_t)SSH_FILEXFER_ATTR_SIZE)
    {
#ifdef WIN32
        ret = SSH_ERROR;
#else
        if(truncate(file_name, z_client_message->attr->size) == -1)
        {
            ret = SSH_ERROR;
            status = unix_errno_to_ssh_status(errno);
        }
#endif
    }

    if(z_client_message->attr->flags & (uint32_t)SSH_FILEXFER_ATTR_PERMISSIONS)
    {
#ifdef WIN32
        ret = SSH_ERROR;
#else
        if(chmod(file_name, z_client_message->attr->permissions & (uint32_t)07777) == -1)
#endif
        {
            ret = SSH_ERROR;
            status = unix_errno_to_ssh_status(errno);
        }
    }

    if(z_client_message->attr->flags & (uint32_t)SSH_FILEXFER_ATTR_ACMODTIME)
    {
        struct utimbuf times;

        times.actime = z_client_message->attr->atime;
        times.modtime = z_client_message->attr->mtime;

        if(utime(file_name, &times) == -1)
        {
            ret = SSH_ERROR;
            status = unix_errno_to_ssh_status(errno);
        }
    }

    if(z_client_message->attr->flags & (uint32_t)SSH_FILEXFER_ATTR_UIDGID)
    {
#ifdef WIN32
        ret = SSH_ERROR;
#else
        if(chown(file_name, z_client_message->attr->uid, z_client_message->attr->gid) == -1)
        {
            ret = SSH_ERROR;
            status = unix_errno_to_ssh_status(errno);
        }
#endif
    }

    sftp_reply_status(z_client_message, status, NULL);

    return(ret);
}

/**
 * @brief Process stat command
 * @param z_client_message Pointer to client message
 * @return SSH_OK or SSH_ERROR
 */
static int process_stat(sftp_client_message z_client_message)
{
    int ret = SSH_OK;
    const char* file_name = sftp_client_message_get_filename(z_client_message);
    struct sftp_attributes_struct attr;
#ifdef WIN32
    struct _stat st;
#else
    struct stat st;
#endif

#ifdef WIN32
    if(_stat(file_name, &st) == 0)
#else
    if(stat(file_name, &st) == 0)
#endif
    {
        stat_to_filexfer_attrib(&st, &attr);
        sftp_reply_attr(z_client_message, &attr);
    }
    else
    {
        int status = unix_errno_to_ssh_status(errno);
        sftp_reply_status(z_client_message, status, NULL);
        ret = SSH_ERROR;
    }

    return(ret);
}

/**
 * @brief Process write command
 * @param z_client_message Pointer to client message
 * @return SSH_OK or SSH_ERROR
 */
static int process_write(sftp_client_message z_client_message)
{
    int ret = SSH_OK;
    FILE* fp = (FILE*)sftp_handle(z_client_message->sftp, z_client_message->handle);

    if(fp != NULL)
    {
        unsigned long n;
        unsigned long len = strlen(ssh_string_get_char(z_client_message->data));

        fseek(fp, z_client_message->offset, SEEK_SET);
        n = fwrite(ssh_string_get_char(z_client_message->data), sizeof(char), len, fp);

        if(n > 0)
        {
            sftp_reply_status(z_client_message, SSH_FX_OK, NULL);
        }
        else
        {
            sftp_reply_status(z_client_message, SSH_FX_FAILURE, "Write error");
        }
    }
    else
    {
        sftp_reply_status(z_client_message, SSH_FX_INVALID_HANDLE, NULL);
        ret = SSH_ERROR;
    }

    return(ret);
}

volatile sig_atomic_t run = 1; /**< Run flag */

/**
 * @brief Process SFTP commands
 * @param z_sftp_sn - Pointer to sftp session
 */
static void process_sftp_commands(sftp_session z_sftp_sn)
{
    int status = SSH_OK;

    while(run == 1)
    {
        int client_message_type;

        sftp_client_message client_message;

        client_message = sftp_get_client_message(z_sftp_sn);

        if(client_message == NULL)
        {
            break;
        }

        client_message_type = sftp_client_message_get_type(client_message);

        switch(client_message_type)
        {
            case SSH_FXP_OPEN:
            {
                status = process_open(client_message);
                break;
            }

            case SSH_FXP_READ:
            {
                status = process_read(client_message);
                break;
            }

            case SSH_FXP_WRITE:
            {
                status = process_write(client_message);
                break;
            }


            case SSH_FXP_CLOSE:
            {
                status = process_close(client_message);
                break;
            }

            case SSH_FXP_LSTAT:
            {
                status = process_lstat(client_message);
                break;
            }

            case SSH_FXP_FSTAT:
            {
                status = process_fstat(client_message);
                break;
            }

            case SSH_FXP_SETSTAT:
            case SSH_FXP_FSETSTAT:
            {
                status = process_setstat(client_message);
                break;
            }

            case SSH_FXP_OPENDIR:
            {
                status = process_opendir(client_message);
                break;
            }
            case SSH_FXP_READDIR:
            {
                status = process_readdir(client_message);
                break;
            }

            case SSH_FXP_REMOVE:
            {
                status = process_remove(client_message);
                break;
            }

            case SSH_FXP_MKDIR:
            {
                status = process_mkdir(client_message);
                break;
            }

            case SSH_FXP_RMDIR:
            {
                status = process_rmdir(client_message);
                break;
            }

            case SSH_FXP_REALPATH:
            {
                status = process_realpath(client_message);
                break;
            }

            case SSH_FXP_STAT:
            {
                status = process_stat(client_message);
                break;
            }

            case SSH_FXP_RENAME:
            {
                status = process_rename(client_message);
                break;
            }

            case SSH_FXP_INIT:
            case SSH_FXP_VERSION:
            case SSH_FXP_READLINK:
            case SSH_FXP_SYMLINK:
            default:
            {
                sftp_reply_status(client_message, SSH_FX_OP_UNSUPPORTED, "Operation not supported");
                printf("Message type %d not implemented\n", client_message_type);
                break;
            }
        }

        sftp_client_message_free(client_message);

        if(status == SSH_ERROR)
        {
            break;
        }
    }
}

volatile sig_atomic_t num_threads = 0; /**< Number of threads */

/**
 * @brief Worker thread
 * @param z_session - Pointer to ssh session
 * @return NULL
 */
static void* worker_thread(void* z_session)
{
    ssh_session session = (ssh_session) z_session;
    ssh_channel chan = NULL;
    sftp_session sftp_sn = NULL;
    int auth = SSH_ERROR;
    int sftp = SSH_ERROR;

    do
    {
        if (ssh_handle_key_exchange(session) != SSH_OK)
        {
            printf("Error ssh_handle_key_exchange: %s\n", ssh_get_error(session));
            break;
        }

        auth = authenticate(session);

        if (auth == SSH_ERROR)
        {
            printf("Error authenticate: %s\n", ssh_get_error(session));
            break;
        }

        chan = open_channel(session);

        if (chan == NULL)
        {
            printf("Error open_channel: %s\n", ssh_get_error(session));
            break;
        }

        sftp = sftp_subsystem_request(session);

        if (sftp == SSH_ERROR)
        {
            printf("Error sftp_subsystem_request: %s\n", ssh_get_error(session));
            break;
        }

        sftp_sn = sftp_server_new(session, chan);

        if(sftp_sn == NULL)
        {
            break;
        }

        if(sftp_server_init(sftp_sn) < 0)
        {
            break;
        }

        process_sftp_commands(sftp_sn);


    }while(0);

    if(sftp_sn != NULL)
    {
        free_handles(sftp_sn);
        sftp_free(sftp_sn);
    }

    ssh_disconnect(session);
    ssh_free(session);

    num_threads--;

    return(NULL);
}

/**
 * @brief sigterm handler
 */
void sigterm_handler(int signal)
{
    run = 0;
}

/**
 * @brief Main function
 * @return SSH_OK or SSH_ERROR
 */
int main()
{
    int ret = SSH_ERROR;
    ssh_bind sshbind = NULL;
#ifndef WIN32
    struct sigaction action;
#endif
    ssh_threads_set_callbacks(ssh_threads_get_pthread());

    ssh_init();

    printf("Starting sftpserver on port %s\n", BINDPORT);

#ifdef WIN32
    /* Catch SIGBREAK */
    signal(SIGBREAK, sigterm_handler);
#else
    /* Catch SIGTERM */
    memset(&action, 0, sizeof(struct sigaction));
    action.sa_handler = sigterm_handler;
    sigaction(SIGTERM, &action, NULL);
#endif
    do
    {
        if(chdir(STR(HOME_DIR)) == -1)
        {
            break;
        }

        init_handle_table();

        if((sshbind = ssh_bind_new()) == NULL)
        {
            break;
        }

        /*if(ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_DSAKEY, STR(SSH_KEYS_DIR) "/ssh_host_dsa_key") < 0)
        {
            break;
        }*/

        if(ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, STR(SSH_KEYS_DIR) "/ssh_host_rsa_key") < 0)
        {
            break;
        }

        if(ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT_STR, BINDPORT ) < 0)
        {
            break;
        }

        if (ssh_bind_listen(sshbind) < 0)
        {
            printf("Error ssh_bind_listen: %s\n", ssh_get_error(sshbind));
            break;
        }

        ret = SSH_OK;

        while(run == 1)
        {
            ssh_session session;
            pthread_attr_t tattr;
            pthread_t thread;
            int error = 1; /* Assume error for now */
            ret = SSH_ERROR;

            session = ssh_new();

            if(session != NULL)
            {
                if(ssh_bind_accept(sshbind, session) == SSH_OK)
                {
                    if(num_threads < MAX_THREADS)
                    {
                        if(pthread_attr_init(&tattr) == 0)
                        {
                            if(pthread_attr_setdetachstate(&tattr,PTHREAD_CREATE_DETACHED) == 0)
                            {
                                if(pthread_create(&thread, &tattr, worker_thread, session) == 0)
                                {
                                    /* All OK */
                                    error = 0;
                                    ret = SSH_OK;
                                    num_threads++;
                                }
                            }
                            
                            if(pthread_attr_destroy(&tattr) != 0)
                            {
                                /* Failed to free attributes */
                                printf("Error pthread_attr_destroy\n");
                            }
                        }
                    }
                    else
                    {
                        printf("No free threads\n");
                        ssh_disconnect(session);
                        ssh_free(session);
                        error = 0;
                        ret = SSH_OK;
                    }
                }
                else
                {
                    printf("Error ssh_bind_accept: %s\n",ssh_get_error(sshbind));
                }
                
                if(error)
                {
                    ssh_disconnect(session);
                    ssh_free(session);
                    run = 0;
                }
            }
            else
            {
                printf("Error ssh_new\n");
                run = 0;
            }
        }
    }while(0);

    ssh_bind_free(sshbind);

#ifdef WIN32_CHECK_FOR_MEMORY_LEAKS
    while(num_threads)
    {
        struct timespec t = {5, 0};
        printf("Number of threads running %d\n", num_threads); 
        pthread_delay_np(&t);
    }
#endif

    if(ssh_finalize() < 0)
    {
        printf("SSH finalize failed\n");
    }

    printf("Sftpserver stopped\n");

#ifdef WIN32_CHECK_FOR_MEMORY_LEAKS
    _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_DEBUG);   
    _CrtDumpMemoryLeaks();
#endif

    return ret;
}
