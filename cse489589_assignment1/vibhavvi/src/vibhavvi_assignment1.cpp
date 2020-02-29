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

#include <iostream>
#include <stdio.h>
#include <cstdio>
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
#include <unistd.h>
#include <algorithm>

#include "../include/global.h"
#include "../include/logger.h"

#define BACKLOG 5
#define STDIN 0
#define TRUE 1
#define BUFFER_SIZE 256

// Forward Declaration
class clientDetails;

// Global connected FD for client
int connectedFd = 0;
using namespace std;

char loggedString[2][20] = {"loggedout", "loggedin"};

int connect_to_server(string &server_ip, string &server_port);
void run_server(string server_port);
void run_client(string port);
void print_ip(string cmd);
void print_server_statistics();
void print_loggedIn_Client_List();
void insertClientPort(string ip, string port);
void logoutClient(string ip);
int presentInLoggedinList(string ip);
int presentInClientList(string str);
bool compare_port(clientDetails a, clientDetails b);

/* clientDetails contains the details about the clients to be maintained at
   the server */
class clientDetails
{
    string client_name;
    string ip;
    string port;
    int num_msg_sent;
    int num_msg_recv;
    int loggedInFlag;

    public:

    clientDetails(string name, string ip, int login) {
        client_name = name;
        this->ip = ip;
        this->port = "";
        loggedInFlag = login;
        num_msg_sent = 0;
        num_msg_recv = 0;
    }

    void login()
    {
        loggedInFlag = 1;
    }

    void logout()
    {
        loggedInFlag = 0;
    }

    void setClientPort(string port)
    {
        this->port = port;     
    }

    string getClientName() {
        return client_name;
    }

    string getClientIp() {
        return ip;
    }

    string getClientPort() {
        return port;
    }

    int numMsgSent() {
        return num_msg_sent;
    }

    int numMsgRecv() {
        return num_msg_recv;
    }

    int loggedIn() {
        return loggedInFlag;
    }
};

vector<clientDetails> loggedInClients; // for server

vector<string> _list; // contains the list of loggedin clients received from the server

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
    if(argc == 3 && strcmp(argv[1], "s") == 0) { // Run as server
        run_server(argv[2]);
    } else if(argc == 3 && strcmp(argv[1], "c") == 0) { // Run as client
        run_client(argv[2]);
    } else {
        cse4589_print_and_log("[%s:ERROR]\n");
    }
    return 0;
}

int connect_to_server(string &server_ip, string &server_port)
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

    cout << "Connected to server " << server_ip.c_str() << ":" << server_port.c_str() << endl;
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

    cout << "Server listening on port: " << server_port.c_str() << endl;
    /* Zero select FD sets */
    FD_ZERO(&master_list);
    FD_ZERO(&watch_list);

    /* Register the listening socket */
    FD_SET(server_socket, &master_list);
    /* Register STDIN */
    FD_SET(STDIN, &master_list);

    int head_socket = server_socket;
    int sock_index;

    string previous_cmd = "";
    while(TRUE) {
        memcpy(&watch_list, &master_list, sizeof(master_list));

        cout << "Select blocking for activity..." << endl;
	    /* select() system call. This will block */
	    int selret = select(head_socket + 1, &watch_list, NULL, NULL, NULL);
	    if(selret < 0)
	        perror("select failed.");
        
        cout << "Select returned" << endl;
        fflush(stdout);

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
                            previous_cmd = tokens[0].c_str();
                            cse4589_print_and_log("[%s:SUCCESS]\n", tokens[0].c_str());
                            cse4589_print_and_log("I, %s, have read and understood the course academic integrity policy.\n", "vibhavvi");
                        } else if(strcmp(tokens[0].c_str(), "IP") == 0) {
                            previous_cmd = tokens[0].c_str();
                            cse4589_print_and_log("[%s:SUCCESS]\n", tokens[0].c_str());
                            print_ip(tokens[0]);
                        } else if(strcmp(tokens[0].c_str(), "PORT") == 0) {
                            previous_cmd = tokens[0].c_str();
                            cse4589_print_and_log("[%s:SUCCESS]\n", tokens[0].c_str());
                            cse4589_print_and_log("PORT:%s\n", server_port.c_str());
                        } else if(strcmp(tokens[0].c_str(), "LIST") == 0) {
                            previous_cmd = tokens[0].c_str();
                            cse4589_print_and_log("[%s:SUCCESS]\n", tokens[0].c_str());
                            print_loggedIn_Client_List(); 
                        } /* Server only commands */
                          else if(strcmp(tokens[0].c_str(), "STATISTICS") == 0) {
                            previous_cmd = tokens[0].c_str();
                            cse4589_print_and_log("[%s:SUCCESS]\n", tokens[0].c_str());
                            print_server_statistics();
                        } else if(strcmp(tokens[0].c_str(), "BLOCKED") == 0) {
                            previous_cmd = tokens[0].c_str();
                            cse4589_print_and_log("[%s:SUCCESS]\n", tokens[0].c_str());
                        } else {
                            cse4589_print_and_log("[%s:ERROR]\n", tokens[0].c_str());
                        }
                        cse4589_print_and_log("[%s:END]\n", tokens[0].c_str());
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

                        struct sockaddr_in addr; 
                        socklen_t addr_len;
                        addr_len = sizeof(addr);
                        getpeername(fdaccept, (struct sockaddr*)&addr, &addr_len);
 
                        char ip[1024];
                        inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip));
                        string ipstr =  std::string(ip);
                        char host[1024];
                        char service[20];
                        getnameinfo((struct sockaddr*)&addr, sizeof(addr), host, sizeof(host), service, sizeof(service), 0);
                        string hostname(host);
                        
                        cout << "Connection accepted from host " << hostname.c_str() << " "
                            << ipstr.c_str() << endl;

                        int i = -1;
                        if((i = presentInLoggedinList(ipstr)) == -1) {
                            clientDetails c(hostname, ipstr, 1);
                            loggedInClients.push_back(c);
                        } else if(loggedInClients[i].loggedIn() == 0) {
                            loggedInClients[i].login();
                        } else {
                            cout << "Client already logged in!!" << endl;
                        }
                        
                        FD_SET(fdaccept, &master_list);
                        if(fdaccept > head_socket) head_socket = fdaccept;
                    }
                    /* Read from existing clients who have connected */
                    else {
                    /* Initialize buffer to receive response */
			            char buffer[1024];
			            memset(buffer, '\0', 1024);
			            if(recv(sock_index, buffer, BUFFER_SIZE, 0) <= 0)
			            {
				            close(sock_index);
				            cout << "Remote Host terminated connection!\n";

				            /* Remove from watched list */
				            FD_CLR(sock_index, &master_list);
			            } else {
	
				            cout << "Client sent: " << buffer << endl;
                            fflush(stdout);
				            cout << "Echoing it back to the remote host..." << endl;
                            fflush(stdout);
                            string buf(buffer), str;
                            str = "";
                            stringstream s(buf);
                            vector<string> tokens;
                            while(getline(s, str, ' ')) {
                                tokens.push_back(str);
                            }
                            s.clear();
                            buf.clear();
                            str.clear();

                            struct sockaddr_in addr;
                            socklen_t addr_len;
                            addr_len = sizeof(addr);
                            getpeername(fdaccept, (struct sockaddr*)&addr, &addr_len);

                            char ip[1024];
                            inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip));
                            string ipstr =  std::string(ip);

                            if(strcmp(tokens[0].c_str(), "LOGIN") == 0)
                            {
                            
                                    insertClientPort(ipstr, tokens[1]);
                                    sort(loggedInClients.begin(), loggedInClients.end(), compare_port);
                                    for(int i = 0; i < loggedInClients.size(); i++)
                                    {
                                        if(strcmp("loggedin", loggedString[loggedInClients[i].loggedIn()]) == 0) {
                                            sprintf(buffer, "%-5d%-35s%-20s%-8s\n", i+1, loggedInClients[i].getClientName().c_str(), loggedInClients[i].getClientIp().c_str(), loggedInClients[i].getClientPort().c_str());
                                            if(-1 == send(fdaccept, buffer, strlen(buffer), 0)) {
                                                perror("Failed to sent record to client");
                                                return;
                                            }
                                            fflush(stdout);
                                        }
                                    }
                                    fflush(stdout);
                                    /*
                                    memset(buffer, '\0', sizeof(buffer));
                                    buffer[0] = 'a';
                               if(-1 == send(fdaccept, buffer , strlen(buffer), 0)) {
                                        perror("Failed to send $ termination symbol");
                                        return;
                                    }
                                    fflush(stdout);
                                    */
                                

                            } else if(strcmp(tokens[0].c_str(), "LOGOUT") == 0) {
                                logoutClient(ipstr);
                            } else if(strcmp(tokens[0].c_str(), "REFRESH") == 0) {
                                for(int i = 0; i < loggedInClients.size(); i++)
                                {
                                    if(strcmp("loggedin", loggedString[loggedInClients[i].loggedIn()]) == 0) {
                                        sprintf(buffer, "%-5d%-35s%-20s%-8s\n", i+1, loggedInClients[i].getClientName().c_str(), loggedInClients[i].getClientIp().c_str(), loggedInClients[i].getClientPort().c_str());
                                        if(-1 == send(fdaccept, buffer, strlen(buffer), 0)) {
                                            perror("Failed to sent record to client");
                                            return;
                                        }
                                        fflush(stdout);
                                    }
                                }

                            } else { }
				            fflush(stdout);
			            }
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

bool compare_port(clientDetails a, clientDetails b)
{
    return stoi(a.getClientPort()) < stoi(b.getClientPort());
}

int presentInClientList(string str) {
    int ret = -1;
    for(int i = 0; i < _list.size(); i++)
    {
        if(str == _list[i])
        {
            ret = i;
            return ret;
        }
    }
    return ret;
}

int presentInLoggedinList(string ip) {
    int ret = -1;
    for(int i = 0; i < loggedInClients.size(); i++)
    {
        if(ip == loggedInClients[i].getClientIp()) {
            ret = i;
            return ret;
        }
    }
    return ret;
}

void logoutClient(string ip)
{
    for(int i = 0; i < loggedInClients.size(); i++)
    {
        if(ip == loggedInClients[i].getClientIp()) {
            loggedInClients[i].logout();
            break;
        }
    }
}

void print_loggedIn_Client_List()
{
    sort(loggedInClients.begin(), loggedInClients.end(), compare_port);
    int j = 1;
    for(int i = 0; i < loggedInClients.size(); i++)
    {
        if(strcmp("loggedin", loggedString[loggedInClients[i].loggedIn()]) == 0) {
           cse4589_print_and_log("%-5d%-35s%-20s%-8s\n", j, loggedInClients[i].getClientName().c_str(), loggedInClients[i].getClientIp().c_str(), loggedInClients[i].getClientPort().c_str());
           j++;
        }
    }
}

void insertClientPort(string ip, string port)
{
    cout << "Insert port number: " << port << " for ip: " << ip << endl;
    for(int i = 0; i < loggedInClients.size(); i++)
    {
        if(ip == loggedInClients[i].getClientIp()) {
            loggedInClients[i].setClientPort(port);
            return;
        }
    }
}

void print_server_statistics()
{
    sort(loggedInClients.begin(), loggedInClients.end(), compare_port);
    for(int i = 0; i < loggedInClients.size(); i++) 
        cse4589_print_and_log("%-5d%-35s%-8d%-8d%-8s\n", i+1, loggedInClients[i].getClientName().c_str(), loggedInClients[i].numMsgSent(), loggedInClients[i].numMsgRecv(), loggedString[loggedInClients[i].loggedIn()]);

}

void run_client(string port)
{
    fd_set master_list, watch_list;
    /* Zero select FD sets */
    FD_ZERO(&master_list);
    FD_ZERO(&watch_list);

    /* Register STDIN*/
    FD_SET(STDIN, &master_list);
    FD_SET(connectedFd, &master_list);
    int head_socket = STDIN; // Initializing head socket to STDIN
    int sock_index;
    string previous_cmd = "";
    while(1) {
        memcpy(&watch_list, &master_list, sizeof(master_list));

        cout << "Select blocking for activity..." << endl;
        /*select() system call. This will block */
        int selret = select(head_socket + 1, &watch_list, NULL, NULL, NULL);
        if(selret < 0)
            perror("select failed");

        cout << "Select returned" << endl;

        /* Check if we have sockets/STDIN to process */
        if(selret > 0) {
            /*Looping through socket descriptors to check which ones are ready*/
            for(sock_index = 0; sock_index <= head_socket; sock_index += 1) {
                if(FD_ISSET(sock_index, &watch_list)) {
                    /*Check if new command on STDIN */
                    if(sock_index == STDIN) {
                        string cmd_input = "";
                        vector<string> tokens;

                        getline(cin, cmd_input);
                        stringstream line(cmd_input);
                        string str = "";
                        while(getline(line, str, ' ')) {
                            tokens.push_back(str);
                        }

                        if(strcmp(tokens[0].c_str(), "AUTHOR") == 0) {
                            previous_cmd = tokens[0].c_str();
                            cse4589_print_and_log("[%s:SUCCESS]\n", tokens[0].c_str());
                            cse4589_print_and_log("I, %s, have read and understood the course academic integrity policy.\n", "vibhavvi");
                        } else if(strcmp(tokens[0].c_str(), "IP") == 0) {
                            previous_cmd = tokens[0].c_str();
                            cse4589_print_and_log("[%s:SUCCESS]\n", tokens[0].c_str());
                            print_ip(tokens[0]);
                        } else if(strcmp(tokens[0].c_str(), "PORT") == 0) {
                            previous_cmd = tokens[0].c_str();
                            cse4589_print_and_log("[%s:SUCCESS]\n", tokens[0].c_str());
                            cse4589_print_and_log("PORT:%s\n", port.c_str());
                        } else if(strcmp(tokens[0].c_str(), "LIST") == 0) {
                            previous_cmd = tokens[0].c_str();
                            cse4589_print_and_log("[%s:SUCCESS]\n", tokens[0].c_str());
                            for(int i = 0; i < _list.size(); i++)
                            {
                                cse4589_print_and_log("%s", _list[i].c_str());
                            }

                        } /* Client only commands start here */
                          else if(strcmp(tokens[0].c_str(), "LOGIN") == 0) {
                            previous_cmd = tokens[0].c_str();
                            cse4589_print_and_log("[%s:SUCCESS]\n", tokens[0].c_str());
                            cout << "Connect to Server " << tokens[1] << ":" << tokens[2];
                            connectedFd = connect_to_server(tokens[1], tokens[2]);
                            cout << "connect returned" << endl;
                            if(connectedFd < 0)
                                perror("Connect failed");

                            ostringstream s;
                            s << "LOGIN " << port;
                            string buf(s.str());
                            s.clear();
                            if(send(connectedFd, buf.c_str(), buf.size(), 0) <= 0) {
                                perror("failed to send the port number to the server");
                                return;
                            }
                            s.clear();
                            buf.clear();
                            fflush(stdout);

                            FD_SET(connectedFd, &master_list);
                            if(connectedFd > head_socket) head_socket = connectedFd;

                        } else if(strcmp(tokens[0].c_str(), "REFRESH") == 0) {
                            previous_cmd = tokens[0].c_str();
                            cse4589_print_and_log("[%s:SUCCESS]\n", tokens[0].c_str());
                            string buf = std::string("REFRESH");
                            if(send(connectedFd, buf.c_str(), buf.size(), 0) <= 0) {
                                perror("failed to send the LOGOUT string to the server");
                                return;
                            }
                            buf.clear();
                            fflush(stdout);

                        } else if(strcmp(tokens[0].c_str(), "SEND") == 0) {
                            previous_cmd = tokens[0].c_str();
                            cse4589_print_and_log("[%s:SUCCESS]\n", tokens[0].c_str());
                            cout << "Send message to client " << tokens[1] << ":" << tokens[2];
                        } else if(strcmp(tokens[0].c_str(), "BROADCAST") == 0) {
                            previous_cmd = tokens[0].c_str();
                            cse4589_print_and_log("[%s:SUCCESS]\n", tokens[0].c_str());
                            cout << "Message " << tokens[1];
                        } else if(strcmp(tokens[0].c_str(), "BLOCK") == 0) {
                            previous_cmd = tokens[0].c_str();
                            cse4589_print_and_log("[%s:SUCCESS]\n", tokens[0].c_str());
                            cout << "Client IP " << tokens[1];
                        } else if(strcmp(tokens[0].c_str(), "UNBLOCK") == 0) {
                            previous_cmd = tokens[0].c_str();
                            cse4589_print_and_log("[%s:SUCCESS]\n", tokens[0].c_str());
                            cout << "Unblock IP " << tokens[1];
                        } else if(strcmp(tokens[0].c_str(), "LOGOUT") == 0) {
                            previous_cmd = tokens[0].c_str();
                            cse4589_print_and_log("[%s:SUCCESS]\n", tokens[0].c_str());
                            
                            string buf = std::string("LOGOUT");
                            if(send(connectedFd, buf.c_str(), buf.size(), 0) <= 0) {
                                perror("failed to send the LOGOUT string to the server");
                                return;
                            }
                            buf.clear();
                            fflush(stdout);
                        } else if(strcmp(tokens[0].c_str(), "EXIT") == 0) {
                            previous_cmd = tokens[0].c_str();
                            cse4589_print_and_log("[%s:SUCCESS]\n", tokens[0].c_str());
                        } else {
                            cse4589_print_and_log("[%s:ERROR]\n", tokens[0].c_str());
                        }
                        cse4589_print_and_log("[%s:END]\n", tokens[0].c_str());
                        cmd_input.clear();
                        line.clear();
                    } else { /* Receive a response from server over connected socket*/
                        char buffer[1024];
                        memset(buffer, '\0', sizeof(buffer));
                        string str = "";
                        if((recv(sock_index, buffer, sizeof(buffer), 0)) <= 0) 
                        {
                            close(sock_index);
                            cout << "Remote Host terminated connection!" << endl;

                            /*Remove from watched list*/
                            FD_CLR(sock_index, &master_list);
                        } else {
                            //str.clear();
                            if(previous_cmd == "LOGIN")
                            {
                                str = std::string(buffer);
                                cout << "Received from server.. " << endl << str << endl;
                                if(-1 == presentInClientList(str))
                                    _list.push_back(str);
                                fflush(stdout);
                            }
                        }
                    }
                } /* end of if loop */
            } /*end of for loop */
        } /* end of if(selret) loop */
    } /* End of infinite while loop */
} /* end of run client function */

void print_ip(string cmd)
{
    int socketfd;
    struct sockaddr_in server, addr;

    memset(&addr, 0, sizeof(addr));

    socketfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(socketfd == -1) {
        perror("Couldn't create socket");
        return;
    }

    server.sin_addr.s_addr = inet_addr("8.8.8.8");
    server.sin_family = AF_INET;
    server.sin_port = htons(53);

    if(-1 == connect(socketfd, (struct sockaddr*)&server, sizeof(server)) < 0) {
        close(socketfd);
        perror("Connect error");
        return;
    }

    socklen_t addr_len = sizeof(addr);
    if(-1 == getsockname(socketfd, (struct sockaddr*)&addr, &addr_len)) {
        perror("getsockname failed");
        return;
    }

    char ip[INET_ADDRSTRLEN] = {'\0'};

    inet_ntop(AF_INET, &addr.sin_addr, ip, INET_ADDRSTRLEN);
    cse4589_print_and_log("IP:%s\n", ip);
}
