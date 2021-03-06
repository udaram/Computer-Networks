#include <unistd.h> 
#include <stdio.h> 
#include <sys/socket.h> 
#include <stdlib.h> 
#include <netinet/in.h> 
#include <string.h> 
#include <arpa/inet.h>
#include<time.h>

#define MAXLINE 1024

void function(FILE* fp,int sockfd){
        char rmessage[MAXLINE];
        char smessage[MAXLINE];
        int n;
        while(1){
                fgets(smessage, MAXLINE, stdin);
                send(sockfd,smessage,strlen(smessage),0);
                n = read(sockfd,rmessage, MAXLINE+1); 
	        rmessage[n] = '\0';
	        printf("Server Message:");
	        fputs(rmessage,stdout);
	}  
}  

int main(int argc,char **argv){
    int sockfd,valread;
    struct sockaddr_in servaddr;
    //char rmessage[MAXLINE+1];
    sockfd = socket(AF_INET,SOCK_STREAM,0);
    bzero(&servaddr,sizeof(servaddr));
    servaddr.sin_family=AF_INET;
    servaddr.sin_port=htons(8080);

    inet_pton(AF_INET,argv[1],&servaddr.sin_addr);

    connect(sockfd,(struct sockaddr *) &servaddr,sizeof(servaddr));
    function(stdin,sockfd);
    
    close(sockfd);
    return 0;

}


