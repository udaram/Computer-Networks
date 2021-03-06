#include <unistd.h> 
#include <stdio.h> 
#include <sys/socket.h> 
#include <stdlib.h> 
#include <netinet/in.h> 
#include <string.h> 
#include <arpa/inet.h>
#include<time.h>

#define MAXLINE 1024
//#define LISTENQ 30


void dg_echo(FILE *fp,int sockfd, struct sockaddr *pcliaddr, socklen_t clilen)
{
	int n;
	socklen_t len;
	char mesg[MAXLINE];

	for ( ; ; ) 
	{
		len = clilen;
		n = recvfrom(sockfd, mesg, MAXLINE, 0, pcliaddr, &len);
		mesg[n]='\0';
		printf("n=%d",n); 
		printf("Client Message:");
		fputs(mesg,stdout);
		fgets(mesg, MAXLINE, fp);
		sendto(sockfd, mesg, strlen(mesg), 0, pcliaddr, len);
	}
}

int main(int argc, char **argv)
{
	int sockfd;
	struct sockaddr_in servaddr, cliaddr;

	if (argc != 2)
	{
		printf("Error: type ./a.out <IPaddress>\n");
		exit(0);

	}  

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);

	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
        //servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(8080);

	if(inet_pton(AF_INET, argv[1], &servaddr.sin_addr) <= 0)
	{
		printf("inet_pton error for %s\n", argv[1]);
		exit(0);
	}
                        
                        
	bind(sockfd, (struct sockaddr *) &servaddr, sizeof(servaddr));

	if(bind < 0)
	{
		printf("Bind Error\n");
		exit(0);

	}

	dg_echo(stdin,sockfd, (struct sockaddr *) &cliaddr, sizeof(cliaddr));
	

	return 0;
}




