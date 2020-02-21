/**
 * @vibhavvi_assignment1
 * @author  Vibhav Virendra Yawalkar <vibhavvi@buffalo.edu>
 * @version 1.0
 *
 * @section LICENSE
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details at
 * http://www.gnu.org/copyleft/gpl.html
 *
 * @section DESCRIPTION
 *
 * This contains the main function. Add further description here....
 */
/* set expandtab ts=4 sw=4 ai */
/* Reference http://man7.org/linux/man-pages/man3/getnameinfo.3.html */
#include <iostream>
#include <stdio.h>
#include <string.h>
#include <cstring>
#include <sstream>
#include <vector>
#include <limits>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netdb.h>
#include <stdlib.h>
#include "../include/global.h"
#include "../include/logger.h"
#include<unistd.h>
#define BACKLOG 5
#define STDIN 0
#define TRUE 1
#define BUFFER_SIZE 256

using namespace std;

int connect_to_host(string &server_ip, string &server_port);
void run_server(string server_port);

class loggedClient
{
    //int serial_no;
    string client_name;
    string ip;
    int port;
    public:
    loggedClient(string name, string ip, int port) {
        name = client_name;
        this->ip = ip;
        this->port = port;
    }
};

vector<loggedClient> loggedInClients;

/**
 * main function
 *
 * @param  argc Number of arguments
 * @param  argv The argument list
 * @return 0 EXIT_SUCCESS
 */
int main(int argc, char **argv)
{
	/*Init. Logger*/
	cse4589_init_log(argv[2]);

	/* Clear LOGFILE*/
    fclose(fopen(LOGFILE, "w"));

	/*Start Here*/
    cout << "argc:" << argc;
    for(int i = 0; i < argc; i++)
	    cout << argv[i] << " ";
    string cmd_input = "";
    vector<string> tokens;
    /* Server Code */
    if(argc == 3 && strcmp(argv[1], "s") == 0) {
        run_server(argv[2]);
    } else if(argc == 2 && strcmp(argv[1], "c") == 0) { // Client code
	    while(1) {
            getline(cin, cmd_input);
	        stringstream line(cmd_input);
	        string str;
	        while(getline(line, str, ' ')) {
                tokens.push_back(str);
	        }

	        if(strcmp(tokens[0].c_str(), "AUTHOR") == 0) {
	            cse4589_print_and_log("[%s:SUCCESS]\n", cmd_input.c_str());
                cse4589_print_and_log("I, %s, have read and understood the course academic integrity policy.\n", "vibhavvi");
            } else if(strcmp(tokens[0].c_str(), "IP") == 0) {
	            cse4589_print_and_log("[%s:SUCCESS]\n", cmd_input.c_str());
	            cse4589_print_and_log("IP:%s\n", "ip_addr");
	        } else if(strcmp(tokens[0].c_str(), "PORT") == 0) {
	            cse4589_print_and_log("[%s:SUCCESS]\n", cmd_input.c_str());
	            cse4589_print_and_log("PORT:%d\n", "7855");
	        } else if(strcmp(tokens[0].c_str(), "LIST") == 0) {
	            cse4589_print_and_log("[%s:SUCCESS]\n", cmd_input.c_str());
	            cse4589_print_and_log("host list\n");
	        } /* Client only commands start here */
	          else if(strcmp(tokens[0].c_str(), "LOGIN") == 0) {
	            cse4589_print_and_log("[%s:SUCCESS]\n", cmd_input.c_str());
	            cout << "Connect to Server " << tokens[1] << ":" << tokens[2];
                int server_fd = connect_to_host(tokens[1], tokens[2]);
                	/*char *buffer = (char*) malloc(sizeof(char)*256);
                	memset(buffer, '\0', 256);

                	if(recv(server_fd, buffer, BUFFER_SIZE, 0) >= 0) {
                    		printf("Server responded: %s", buffer);
                    		fflush(stdout);
                	}
			*/
	        } else if(strcmp(tokens[0].c_str(), "REFRESH") == 0) {
	            cse4589_print_and_log("[%s:SUCCESS]\n", cmd_input.c_str());

	        } else if(strcmp(tokens[0].c_str(), "SEND") == 0) {
	            cse4589_print_and_log("[%s:SUCCESS]\n", cmd_input.c_str());
	            cout << "Send message to client " << tokens[1] << ":" << tokens[2];
	        } else if(strcmp(tokens[0].c_str(), "BROADCAST") == 0) {
	            cse4589_print_and_log("[%s:SUCCESS]\n", cmd_input.c_str());
	            cout << "Message " << tokens[1];
	        } else if(strcmp(tokens[0].c_str(), "BLOCK") == 0) {
                cse4589_print_and_log("[%s:SUCCESS]\n", cmd_input.c_str());
	            cout << "Client IP " << tokens[1];
	        } else if(strcmp(tokens[0].c_str(), "UNBLOCK") == 0) {
	            cse4589_print_and_log("[%s:SUCCESS]\n", cmd_input.c_str());
	            cout << "Unblock IP " << tokens[1];
	        } else if(strcmp(tokens[0].c_str(), "LOGOUT") == 0) {
	            cse4589_print_and_log("[%s:SUCCESS]\n", cmd_input.c_str());
	        } else if(strcmp(tokens[0].c_str(), "EXIT") == 0) {
                cse4589_print_and_log("[%s:SUCCESS]\n", cmd_input.c_str());
	        } else {
	            cse4589_print_and_log("[%s:ERROR]\n", cmd_input.c_str());
            }
        }
    }
    cse4589_print_and_log("[%s:END]\n", cmd_input.c_str());
    return 0;
}

int connect_to_host(string &server_ip, string &server_port)
{
    struct addrinfo hints, *res;

    /* Set up hints structure */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    /* Fill up address structures */
    if(getaddrinfo(server_ip.c_str(), server_port.c_str(), &hints, &res) != 0)
        perror("getaddrinfo failed");

    /* Create Socket */
    int fdsocket = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if(fdsocket < 0)
        perror("Failed to create socket");

    /* Connect or login to the server */
    if(connect(fdsocket, res->ai_addr, res->ai_addrlen) < 0)
        perror("Connect failed");

    cse4589_print_and_log("Connected to server %s:%s", server_ip.c_str(), server_port.c_str());
    freeaddrinfo(res);
    return fdsocket;
}

void run_server(string server_port) {
    struct sockaddr_in client_addr;
    struct addrinfo hints, *res;
    fd_set master_list, watch_list;
    int fdaccept = 0;
    socklen_t caddr_len;

    /* Set up hints structure */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    /* Fill up address structures */
    if(getaddrinfo(NULL, server_port.c_str(), &hints, &res ) != 0)
        perror("getaddrinfo failed");

    /* Socket */
    int server_socket = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if(server_socket < 0)
	perror("Cannot create socket");

    /* Bind */
    if(bind(server_socket, res->ai_addr, res->ai_addrlen) < 0)
	perror("Bind failed");

    freeaddrinfo(res);

    /* Listen */
    if(listen(server_socket, BACKLOG) < 0)
	perror("Unable to listen on port");

    cse4589_print_and_log("Server listening on port: %s\n", server_port.c_str());
    /* Zero select FD sets */
    FD_ZERO(&master_list);
    FD_ZERO(&watch_list);

    /* Register the listening socket */
    FD_SET(server_socket, &master_list);
    /* Register STDIN */
    FD_SET(STDIN, &master_list);

    int head_socket = server_socket;
    int sock_index;	
    while(TRUE) {
        memcpy(&watch_list, &master_list, sizeof(master_list));

	    /* select() system call. This will block */
	    int selret = select(head_socket + 1, &watch_list, NULL, NULL, NULL);
	    if(selret < 0)
	        perror("select failed.");

        cse4589_print_and_log("Select returned\n");
	    /* Check if we have sockets/STDIN to process */
	    if(selret > 0) {
	        /* Looping through socket descriptors to check which ones are ready */
	        for(sock_index = 0; sock_index <= head_socket; sock_index +=1) {
                if(FD_ISSET(sock_index, &watch_list)) {
                
                    /* Check if new command on STDIN */
                    if(sock_index == STDIN) {
                        string cmd_input = "";
                        vector<string> tokens;
                        
                        getline(cin, cmd_input);
                        stringstream line(cmd_input);
                        
                        string str = "";
                        while(getline(line, str, ' ')) {
                            tokens.push_back(str);
                        }

                        if(strcmp(tokens[0].c_str(), "AUTHOR") == 0)
                        {
                            cse4589_print_and_log("[%s:SUCCESS]\n", cmd_input.c_str());
                            cse4589_print_and_log("I, %s, have read and understood the course academic integrity policy.\n", "vibhavvi");
                        } else if(strcmp(tokens[0].c_str(), "IP") == 0) {
                            cse4589_print_and_log("[%s:SUCCESS]\n", cmd_input.c_str());
                            cse4589_print_and_log("IP:%s\n", "ip_addr");
                        } else if(strcmp(tokens[0].c_str(), "PORT") == 0) {
                            cse4589_print_and_log("[%s:SUCCESS]\n", cmd_input.c_str());
                            cse4589_print_and_log("PORT:%d\n", 7855);
                        } else if(strcmp(tokens[0].c_str(), "LIST") == 0) {
                            cse4589_print_and_log("[%s:SUCCESS]\n", cmd_input.c_str());
                            cse4589_print_and_log("host list\n");
                        } /* Server only commands */
                          else if(strcmp(tokens[0].c_str(), "STATISTICS") == 0) {
                            cse4589_print_and_log("[%s:SUCCESS]\n", cmd_input.c_str());
                            cse4589_print_and_log("Statistics\n");
                        } else if(strcmp(tokens[0].c_str(), "BLOCKED") == 0) {
                            cse4589_print_and_log("[%s:SUCCESS]\n", cmd_input.c_str());
                        } else {/*NOT USED */}
                        cse4589_print_and_log("[%s:END]\n", cmd_input.c_str());
                        cmd_input.clear();
                        line.clear();
                    }
                    /* Check if new client is requesting connection */
                    else if(sock_index == server_socket) {
                        caddr_len = sizeof(client_addr);
                        fdaccept = accept(server_socket, (struct sockaddr*)&client_addr, &caddr_len);
                        if(fdaccept < 0)
                            perror("Accept failed.");
                        /* Add to watched socket list */
                        cse4589_print_and_log("Connection accepted from host");
                        struct sockaddr_storage addr;
                        struct sockaddr sa;
                        socklen_t len;
                        len = sizeof(addr);
                        getpeername(fdaccept, (struct sockaddr*)&addr, &len);
                        
                        struct sockaddr_in *s = (struct sockaddr_in*)&addr;
                        char ip[1024];
                        inet_ntop(AF_INET, &s->sin_addr, ip, sizeof(ip));
                        string ipstr(ip);
                        char host[1024];
                        char service[20];
                        getnameinfo(&sa, sizeof(sa), host, sizeof(host), service, sizeof(service), 0);
                        string hostname(host);
                        loggedClient c(hostname, ipstr , ntohs(s->sin_port));
                        
                        cse4589_print_and_log("Connection accepted from host %s %s %d", hostname.c_str(), ipstr.c_str(), ntohs(s->sin_port));
                        FD_SET(fdaccept, &master_list);
                        if(fdaccept > head_socket) head_socket = fdaccept;
                    }
                    /* Read from existing clients who have connected */
                    else {
                    /* Initialize buffer to receive response */
			char * buffer = (char*) malloc(sizeof(char)*256);
			memset(buffer, '\0', 256);
			if(recv(sock_index, buffer, BUFFER_SIZE, 0) <= 0)
			{
				close(sock_index);
				cout << "Remote Host terminated connection!\n";

				/* Remove from watched list */
				FD_CLR(sock_index, &master_list);
			} else {
	
				printf("CLient sent: %s \n", buffer);
				printf("Echoing it back to the remote host...");
				if(send(fdaccept, buffer, strlen(buffer), 0) == strlen(buffer))
				printf("DOne!\n");
				fflush(stdout);
			}
			free(buffer);
                    }
                    //cin.clear();
                    //fflush(stdin);
                    //fflush(stdout);
                    //cin.ignore(numeric_limits<streamsize>::max(), '\n');
                }
            }
        }
    }
} /*end of run_server func */
