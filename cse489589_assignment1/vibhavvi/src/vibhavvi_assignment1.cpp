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
#include <fstream>
#include <vector>
#include <limits>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netdb.h>
#include <stdlib.h>
#include <unistd.h>
#include <algorithm>
#include <unordered_map>
#include "../include/global.h"
#include "../include/logger.h"

#define BACKLOG 5
#define STDIN 0
#define TRUE 1
#define BUFFER_SIZE 512

void log_print(char* filename, int line, char *fmt,...);
#define LOG_PRINT(...) log_print(__FILE__, __LINE__, __VA_ARGS__ )


//logger.c
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include "logger.h"
FILE *fp ;
static int SESSION_TRACKER; //Keeps track of session

char* print_time()
{
    int size = 0;
    time_t t;
    char *buf;
    
    t=time(NULL); /* get current calendar time */
    
    char *timestr = asctime( localtime(&t) );
    timestr[strlen(timestr) - 1] = 0;  //Getting rid of \n
    
    size = strlen(timestr)+ 1 + 2; //Additional +2 for square braces
    buf = (char*)malloc(size);
    
    memset(buf, 0x0, size);
    snprintf(buf,size,"[%s]", timestr);
   
    return buf;
}
void log_print(char* filename, int line, char *fmt,...)
{
    va_list         list;
    char            *p, *r;
    int             e;

    if(SESSION_TRACKER > 0)
      fp = fopen ("/tmp/log.txt","a+");
    else
      fp = fopen ("/tmp/log.txt","w");
    
    //fprintf(fp,"%s ",print_time());
    fprintf(fp,"[%s][line: %d] ",filename,line);
    va_start( list, fmt );

    for ( p = fmt ; *p ; ++p )
    {
        if ( *p != '%' )//If simple string
        {
            fputc( *p,fp );
        }
        else
        {
            switch ( *++p )
            {
                /* string */
            case 's':
            {
                r = va_arg( list, char * );

                fprintf(fp,"%s", r);
                continue;
            }

            /* integer */
            case 'd':
            {
                e = va_arg( list, int );

                fprintf(fp,"%d", e);
                continue;
            }

            default:
                fputc( *p, fp );
            }
        }
    }
    va_end( list );
    fputc( '\n', fp );
    SESSION_TRACKER++;
    fclose(fp);
}


// Forward Declaration
class clientDetails;

// Global connected FD for client
//int connectedFd = 0;
using namespace std;

char loggedString[2][20] = {"loggedout", "loggedin"};
unordered_map<string, int> ip_fd_map;
unordered_map<string, vector<string>> bufferedMessageList;
unordered_map<string, vector<string>> blockedList;

int connect_to_server(string &server_ip, string &server_port);
void run_server(unsigned int server_port);
void run_client(unsigned int port);
void print_ip(string cmd);
void print_server_statistics();
void print_loggedIn_Client_List();
void insertClientPort(string ip, string port);
void logoutClient(string ip);
int presentInLoggedinList(string ip);
int presentInClientList(string str);
bool compare_port(clientDetails a, clientDetails b);
int sendall(int s, char *buf, int *len);
bool isBlocked(string clientIP, string IP);
void printBlockedClientDetails(string clientIp); /* Pass the IP of the client who's blocked list is to be displayed */
void unblock(string clientIP, string ipToUnblock);
int recvall(int s, char *buf, int len);

/* clientDetails contains the details about the clients to be maintained at
   the server */
class clientDetails
{
    string client_name;
    string ip;
    unsigned int port;
    int num_msg_sent;
    int num_msg_recv;
    int loggedInFlag;

    public:

    clientDetails(string name, string ip, int login) {
        client_name = name;
        this->ip = ip;
        this->port = 0;
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

    void setClientPort(unsigned int port)
    {
        this->port = port;     
    }

    string getClientName() {
        return client_name;
    }

    string getClientIp() {
        return ip;
    }

    unsigned int getClientPort() {
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

ofstream myfile;

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


    myfile.open("/tmp/grader_log.txt");
	/*Start Here*/
    if(argc == 3 && strcmp(argv[1], "s") == 0) { // Run as server
        run_server((unsigned int)stol(argv[2]));
    } else if(argc == 3 && strcmp(argv[1], "c") == 0) { // Run as client
        run_client((unsigned int)stol(argv[2]));
    } else {
        cse4589_print_and_log("[ERROR]\n");
        
        LOG_PRINT("[ERROR]\n");
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

    freeaddrinfo(res);
    return fdsocket;
}

void run_server(unsigned int server_port) {
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
    string addr_info_port = to_string(server_port);
    if(getaddrinfo(NULL, addr_info_port.c_str(), &hints, &res ) != 0)
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

    cout << "Server listening on port: " << server_port << endl;
    LOG_PRINT("Server listening on port: %d\n", server_port);
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

        cout << "Select blocking for activity..." << endl;
        LOG_PRINT("Select blocking for activity\n");
	    /* select() system call. This will block */
	    int selret = select(head_socket + 1, &watch_list, NULL, NULL, NULL);
	    if(selret < 0)
	        perror("select failed.");
        
        cout << "Select returned" << endl;
        LOG_PRINT("Select returned\n");
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
                            cse4589_print_and_log("[%s:SUCCESS]\n", tokens[0].c_str());
                            LOG_PRINT("[%s:SUCCESS]\n", tokens[0].c_str());
                            cse4589_print_and_log("I, %s, have read and understood the course academic integrity policy.\n", "vibhavvi");
                            string name = "vibhavvi";
                            LOG_PRINT("I, %s, have read and understood the course academic integrity policy.\n", name.c_str());
                        } else if(strcmp(tokens[0].c_str(), "IP") == 0) {
                            cse4589_print_and_log("[%s:SUCCESS]\n", tokens[0].c_str());
                            LOG_PRINT("[%s:SUCCESS]\n", tokens[0].c_str());
                            print_ip(tokens[0]);
                        } else if(strcmp(tokens[0].c_str(), "PORT") == 0) {
                            cse4589_print_and_log("[%s:SUCCESS]\n", tokens[0].c_str());
                            LOG_PRINT("[%s:SUCCESS]\n", tokens[0].c_str());
                            cse4589_print_and_log("PORT:%d\n", server_port);
                            LOG_PRINT("PORT:%d\n", server_port);
                        } else if(strcmp(tokens[0].c_str(), "LIST") == 0) {
                            cse4589_print_and_log("[%s:SUCCESS]\n", tokens[0].c_str());
                            LOG_PRINT("[%s:SUCCESS]\n", tokens[0].c_str());
                            print_loggedIn_Client_List(); 
                        } /* Server only commands */
                          else if(strcmp(tokens[0].c_str(), "STATISTICS") == 0) {
                            cse4589_print_and_log("[%s:SUCCESS]\n", tokens[0].c_str());
                            print_server_statistics();
                        } else if(strcmp(tokens[0].c_str(), "BLOCKED") == 0) {
                            cse4589_print_and_log("[%s:SUCCESS]\n", tokens[0].c_str());
                            printBlockedClientDetails(tokens[1]);
                        } else {
                            LOG_PRINT("[%s:ERROR]\n", tokens[0].c_str());
                            cse4589_print_and_log("[%s:ERROR]\n", tokens[0].c_str());
                        }
                        cse4589_print_and_log("[%s:END]\n", tokens[0].c_str());
                        LOG_PRINT("[%s:END]\n", tokens[0].c_str());
                        cmd_input.clear();
                        line.clear();
                    }
                    /* Check if new client is requesting connection */
                    else if(sock_index == server_socket) {
                        caddr_len = sizeof(client_addr);
                        int fdaccept = accept(server_socket, (struct sockaddr*)&client_addr, &caddr_len);
                        if(fdaccept < 0)
                            perror("Accept failed.");
                        /* Add to watched socket list */
                        FD_SET(fdaccept, &master_list);
                        if(fdaccept > head_socket) head_socket = fdaccept;

                        struct sockaddr_in addr; 
                        socklen_t addr_len = sizeof(addr);
                        getpeername(fdaccept, (struct sockaddr*)&addr, &addr_len);
 
                        char ip[INET_ADDRSTRLEN];
                        memset(ip, '\0', INET_ADDRSTRLEN);
                        inet_ntop(AF_INET, &addr.sin_addr, ip, INET_ADDRSTRLEN);
                        string ipstr =  std::string(ip); // Storing the client IP in the string ipstr

                        /* Add to the ip-fd map */
                        ip_fd_map[ipstr] = fdaccept;

                        char host[BUFFER_SIZE];
                        memset(host, '\0', sizeof(host));
                        char service[BUFFER_SIZE];
                        getnameinfo((struct sockaddr*)&addr, sizeof(addr), host, sizeof(host), service, sizeof(service), 0);
                        string hostname(host);
                        
                        cout << "Connection accepted from Host:" << hostname << " IP:" << ipstr << endl;
                        LOG_PRINT("COnnection accepted from Host:%s IP:%s\n", hostname.c_str(), ipstr.c_str());
                        int i;
                        if((i = presentInLoggedinList(ipstr)) == -1) { /* If not in the loggedin list, add client to the list*/
                            clientDetails c(hostname, ipstr, 1);
                            loggedInClients.push_back(c);
                        } else if(loggedInClients[i].loggedIn() == 0) {/* If present in the list but logged out */
                            loggedInClients[i].login();
                        } else {
                            cout << "Client already logged in!!" << endl;
                            LOG_PRINT("CLient already logged in !!\n");
                        }
                    }
                    /* Read from existing clients who have connected */
                    else {
                        /* Initialize buffer to receive response */
			            char buffer[BUFFER_SIZE];
			            memset(buffer, '\0', BUFFER_SIZE);
                        int len = sizeof(buffer);

			            if(recv(sock_index, buffer, BUFFER_SIZE, 0) <= 0)
			            {
				            close(sock_index);
				            cout << "Remote Host terminated connection!\n";
                            LOG_PRINT("Remote Host terminated connection!\n");

				            /* Remove from watched list */
				            FD_CLR(sock_index, &master_list);
			            } else {

                            struct sockaddr_in addr;
                            socklen_t addr_len = sizeof(addr);
                            getpeername(sock_index, (struct sockaddr*)&addr,  &addr_len);
                            char ip[INET_ADDRSTRLEN];
                            memset(ip, '\0', INET_ADDRSTRLEN);
                            inet_ntop(AF_INET, &addr.sin_addr, ip, INET_ADDRSTRLEN);
                            /* Contains the IP of the client which is being served, this is also used later */
                            string ipstr = std::string(ip);

                            string buf(buffer), str;
                            str = "";
				            
                            cout << "Data received :" << buf.c_str() << " from client:" << ipstr << endl;
                            LOG_PRINT("Data received : %s from client %s\n", buf.c_str(), ipstr.c_str());
                            fflush(stdout);
                            
                            /* Interpret the data sent by the client */
                            stringstream s(buf);
                            vector<string> tokens;
                            while( str != std::string("SEND") && getline(s, str, ' ')) {
                                tokens.push_back(str);
                            }
                            s.clear();
                            buf.clear();
                            str.clear();

                            if(strcmp(tokens[0].c_str(), "LOGIN") == 0)
                            {   
                                char recordBuffer[80];
                                memset(recordBuffer, '\0', sizeof(recordBuffer));

                                insertClientPort(ipstr, tokens[1]);;
                                LOG_PRINT("Starting to sort loggedinCLients\n");
                                sort(loggedInClients.begin(), loggedInClients.end(), compare_port);
                                LOG_PRINT("DOne with sorting loggedinClients\n");
                                string records = ""; /* List of all loggedin clients*/
                                for(int i = 0; i < loggedInClients.size(); i++)
                                {
                                    if(strcmp("loggedin", loggedString[loggedInClients[i].loggedIn()]) == 0) {
                                        sprintf(recordBuffer, "%-5d%-35s%-20s%-8d\n", i+1, loggedInClients[i].getClientName().c_str(), loggedInClients[i].getClientIp().c_str(), loggedInClients[i].getClientPort());
                                        string rec(recordBuffer);
                                        records += rec;
                                        records += "$";
                                        rec.clear();
                                        memset(recordBuffer, '\0', sizeof(recordBuffer));
                                    }
                                }
                                string msg = std::string("LOGIN ");
                                msg += records;
                                 
                                cout << "Message sent by the server to client " << msg << " length: " << msg.length() << endl;
                                LOG_PRINT("Message sent by the server to client %s length: %d\n", msg.c_str(), msg.length());
                                int len = msg.length();
                                if(-1 == sendall(sock_index, (char*)msg.c_str(), &len)) {
                                    perror("Failed to send loggedin client list");
                                    return;
                                }
                                fflush(stdout);

                            } else if(strcmp(tokens[0].c_str(), "LOGOUT") == 0) {
                                logoutClient(ipstr);
                            } else if(strcmp(tokens[0].c_str(), "REFRESH") == 0) {
                                char recordBuffer[80];
                                memset(recordBuffer, '\0', sizeof(recordBuffer));

                                string records = "";
                                for(int i = 0; i < loggedInClients.size(); i++)
                                {
                                    if(strcmp("loggedin", loggedString[loggedInClients[i].loggedIn()]) == 0) {
                                        sprintf(recordBuffer, "%-5d%-35s%-20s%-8d\n", i+1, loggedInClients[i].getClientName().c_str(), loggedInClients[i].getClientIp().c_str(), loggedInClients[i].getClientPort());
                                        string rec(recordBuffer);
                                        records += rec;
                                        records += "$";
                                        rec.clear();
                                        memset(recordBuffer, '\0', sizeof(recordBuffer));
                                    }
                                }
                                string msg = std::string("REFRESH ");
                                msg += records;

                                cout << "Message sent by the server to client " << msg << " length: " << msg.length() << endl;
                                LOG_PRINT("MEssage sent by the server to client %s %d:\n", msg.c_str(), msg.length());
                                int len = msg.length();
                                if(-1 == sendall(sock_index, (char*)msg.c_str(), &len)) {
                                    perror("Failed to send loggedin client list");
                                    return;
                                }
                                fflush(stdout);

                            } else if(strcmp(tokens[0].c_str(), "SEND") == 0) {
                                if(getline(s, str, ' '))
                                    tokens.push_back(str);
                                string _l = s.str();
                                size_t pos = _l.find(" ");
                                string tmp = _l.substr(pos + 1);
                                pos = tmp.find(" ");
                                string text_msg = tmp.substr(pos + 1);

                                string dest_ip = tokens[1];
                                string msg = "";
                                msg += tokens[0];
                                msg += " ";
                                msg += ipstr;
                                msg += " ";
                                msg += text_msg;
                                cout << "Received send request at the server" << msg << endl;
                                LOG_PRINT("Received send request at the server %s", msg.c_str());
                                if(!isBlocked(dest_ip, ipstr)) { /* Check if destination IP has blocked the sender */
                                    int len = strlen(msg.c_str());
                                    if(-1 == sendall(ip_fd_map[dest_ip], (char*)msg.c_str(), &len))
                                    {
                                        perror("Failed to send the message to the destination");
                                        return;
                                    }
                                    cse4589_print_and_log("[%s:SUCCESS]\n", "RELAYED");
                                    cse4589_print_and_log("msg from:%s, to:%s\n[msg]:%s\n",ipstr.c_str(), dest_ip.c_str(), text_msg.c_str());
                                    cse4589_print_and_log("[%s:END]\n", "RELAYED");
                                    LOG_PRINT("[%s:SUCCESS]\n", "RELAYED");
                                    LOG_PRINT("msg from:%s, to:%s\n[msg]:%s\n",ipstr.c_str(), dest_ip.c_str(), text_msg.c_str());
                                    LOG_PRINT("[%s:END]\n", "RELAYED");
                                }
                                fflush(stdout);
                            } else if(strcmp(tokens[0].c_str(), "BROADCAST") == 0){
                                string text_msg = tokens[1];
                                string  msg ="";
                                msg += tokens[0];
                                msg += " ";
                                msg += ipstr;
                                msg += " ";
                                msg += text_msg;

                                cout << "Received broadcast request at the server" << msg << endl;
                                int len = strlen(msg.c_str());

                                for(int i = 0; i < loggedInClients.size(); i++)
                                {
                                    if(!isBlocked(loggedInClients[i].getClientIp(), ipstr)) {
                                        if(strcmp("loggedin", loggedString[loggedInClients[i].loggedIn()]) == 0 && loggedInClients[i].getClientIp() != ipstr) {
                                            if(-1 == sendall(ip_fd_map[loggedInClients[i].getClientIp()], (char*)msg.c_str(), &len)) {
                                                perror("Failed to send the message to the destination");
                                                return;
                                            }
                                            cse4589_print_and_log("[%s:SUCCESS]\n", "RELAYED");
                                            cse4589_print_and_log("msg from:%s, to:%s\n[msg]:%s\n",ipstr.c_str(), "255.255.255.255", text_msg.c_str());
                                            cse4589_print_and_log("[%s:END]\n", "RELAYED");
                                            LOG_PRINT("[%s:SUCCESS]\n", "RELAYED");
                                            LOG_PRINT("msg from:%s, to:%s\n[msg]:%s\n",ipstr.c_str(), "255.255.255.255", text_msg.c_str());
                                            LOG_PRINT("[%s:END]\n", "RELAYED");
                                        } else { /* Buffer the message for loggedout clients */
                                            bufferedMessageList[loggedInClients[i].getClientIp()].push_back(text_msg); 
                                        }
                                    }
                                }
                            } else if(strcmp(tokens[0].c_str(), "BLOCK") == 0) {
                                string blockedIP = tokens[1];
                                cout << "Received blocking request from " << ipstr << " for " << tokens[1];
                                blockedList[ipstr].push_back(tokens[1]);
                            } else if(strcmp(tokens[0].c_str(), "UNBLOCK") == 0) {
                                string ipToUnblock = tokens[1];
                                cout << "Received un blocking request from " << ipstr << " for " << tokens[1];
                                unblock(ipstr, tokens[1]);
                            } else {}
                        }
                    }
                }
            }
        }
    }
    myfile.close();
} /*end of run_server func */

void unblock(string clientIP, string ipToUnblock)
{
    for(auto itr = blockedList[clientIP].begin(); itr != blockedList[clientIP].end(); ++itr)
    {
        if(*itr == ipToUnblock) {
            blockedList[clientIP].erase(itr);
            return;
        }
    }
}

bool isBlocked(string clientIP, string IP ) {
    vector<string> blockedClients = blockedList[clientIP];
    for(int i = 0; i < blockedClients.size(); i++)
        if(blockedClients[i] == IP)
            return true;
    return false;
}

int recvall(int s, char *buf, int len)
{
    int total = 0; // total bytes read

    while(total < len) {
        int n = recv(s, buf+total, (len-total), 0);
        if(n <= 0 || buf[n] == '#') { break; }
        total += n;
    }

    if(buf[total] == '#') {
        buf[total] = '\0';
        return 1;
    }
    return 0;
}

int sendall(int s, char *buf, int *len)
{
    int total = 0; // how many bytes we've sent
    int bytesleft = *len; // how may we have left to send
    int  n;

    while(total < *len) {
        n = send(s, buf+total, bytesleft, 0);
        if(n == -1) { break; }
        total += n;
        bytesleft -= n;
    }

    *len = total; // return number actually sent here
    return n == -1 ? -1 : 0;
}

bool compare_port(clientDetails a, clientDetails b)
{
    return a.getClientPort() < b.getClientPort();
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
           LOG_PRINT("%-5d%-35s%-20s%-8d\n", j, loggedInClients[i].getClientName().c_str(), loggedInClients[i].getClientIp().c_str(), loggedInClients[i].getClientPort());
           cse4589_print_and_log("%-5d%-35s%-20s%-8d\n", j, loggedInClients[i].getClientName().c_str(), loggedInClients[i].getClientIp().c_str(), loggedInClients[i].getClientPort());
           j++;
        }
    }
}

void insertClientPort(string ip, string port)
{
    cout << "Insert port number: " << (unsigned int)stol(port) << " for ip: " << ip << endl;
    LOG_PRINT("Insert port number: %d for ip %s", (unsigned int)stol(port), ip.c_str());
    for(int i = 0; i < loggedInClients.size(); i++)
    {
        if(ip == loggedInClients[i].getClientIp()) {
            loggedInClients[i].setClientPort((unsigned int)(stol(port)));
            return;
        }
    }
    LOG_PRINT("Exit insert Client port\n");
}

void print_server_statistics()
{
    sort(loggedInClients.begin(), loggedInClients.end(), compare_port);
    for(int i = 0; i < loggedInClients.size(); i++) {
        LOG_PRINT("%-5d%-35s%-8d%-8d%-8s\n", i+1, loggedInClients[i].getClientName().c_str(), loggedInClients[i].numMsgSent(), loggedInClients[i].numMsgRecv(), loggedString[loggedInClients[i].loggedIn()]);
        cse4589_print_and_log("%-5d%-35s%-8d%-8d%-8s\n", i+1, loggedInClients[i].getClientName().c_str(), loggedInClients[i].numMsgSent(), loggedInClients[i].numMsgRecv(), loggedString[loggedInClients[i].loggedIn()]);
    }
}

void printBlockedClientDetails(string clientIp)
{
    vector<clientDetails> blockedClientList;
    vector<string> blockedIps = blockedList[clientIp];
    
    for(int k = 0; k < blockedIps.size(); k++)
    {
        for(int i = 0; i < loggedInClients.size(); i++)
        {
            if(loggedInClients[i].getClientIp() == blockedIps[k]) {
                clientDetails c(loggedInClients[i].getClientName(), loggedInClients[i].getClientIp().c_str(), 1);
                c.setClientPort(loggedInClients[i].getClientPort());
                blockedClientList.push_back(c);
            }
        }
    }

    sort(blockedClientList.begin(), blockedClientList.end(), compare_port);
    int j = 1;
    for(int i = 0; i < blockedClientList.size(); i++)
    {
        LOG_PRINT("%-5d%-35s%-20s%-8d\n", j, blockedClientList[i].getClientName().c_str(), blockedClientList[i].getClientIp().c_str(), blockedClientList[i].getClientPort());
        cse4589_print_and_log("%-5d%-35s%-20s%-8d\n", j, blockedClientList[i].getClientName().c_str(), blockedClientList[i].getClientIp().c_str(), blockedClientList[i].getClientPort());
        j++;
    }
}

void run_client(unsigned int port)
{
    int connectedFd = -1;
    fd_set master_list, watch_list;
    /* Zero select FD sets */
    FD_ZERO(&master_list);
    FD_ZERO(&watch_list);

    /* Register STDIN*/
    FD_SET(STDIN, &master_list);
    //FD_SET(connectedFd, &master_list);
    int head_socket = STDIN; // Initializing head socket to STDIN
    int sock_index;

    LOG_PRINT("CLient running on port %d\n", port);
    while(1) {
        memcpy(&watch_list, &master_list, sizeof(master_list));

        cout << "Select blocking for activity..." << endl;
        LOG_PRINT("Select blocking for activity...\n");
        /*select() system call. This will block */
        int selret = select(head_socket + 1, &watch_list, NULL, NULL, NULL);
        if(selret < 0)
            perror("select failed");

        cout << "Select returned" << endl;
        LOG_PRINT("Select returned\n");

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
                        while(str != std::string("SEND") && getline(line, str, ' ')) {
                            tokens.push_back(str);
                        }


                        if(strcmp(tokens[0].c_str(), "AUTHOR") == 0) {
                            LOG_PRINT("[%s:SUCCESS]\n", tokens[0].c_str());
                            LOG_PRINT("I, %s, have read and understood the course academic integrity policy.\n", "vibhavvi");

                            cse4589_print_and_log("[%s:SUCCESS]\n", tokens[0].c_str());
                            cse4589_print_and_log("I, %s, have read and understood the course academic integrity policy.\n", "vibhavvi");
                        } else if(strcmp(tokens[0].c_str(), "IP") == 0) {
                            LOG_PRINT("[%s:SUCCESS]\n", tokens[0].c_str());
                            cse4589_print_and_log("[%s:SUCCESS]\n", tokens[0].c_str());
                            print_ip(tokens[0]);
                        } else if(strcmp(tokens[0].c_str(), "PORT") == 0) {
                            LOG_PRINT("[%s:SUCCESS]\n", tokens[0].c_str());
                            LOG_PRINT("PORT:%d\n", port);

                            cse4589_print_and_log("[%s:SUCCESS]\n", tokens[0].c_str());
                            cse4589_print_and_log("PORT:%d\n", port);
                        } else if(strcmp(tokens[0].c_str(), "LIST") == 0) {
                            LOG_PRINT("[%s:SUCCESS]\n", tokens[0].c_str());
                            cse4589_print_and_log("[%s:SUCCESS]\n", tokens[0].c_str());
                            for(int i = 0; i < _list.size(); i++)
                            {
                                LOG_PRINT("%s", _list[i].c_str());
                                cse4589_print_and_log("%s", _list[i].c_str());
                            }

                        } /* Client only commands start here */
                          else if(strcmp(tokens[0].c_str(), "LOGIN") == 0) {
                            LOG_PRINT("[%s:SUCCESS]\n", tokens[0].c_str());
                            cse4589_print_and_log("[%s:SUCCESS]\n", tokens[0].c_str());
                            cout << "Connect to Server " << tokens[1] << ":" << tokens[2];
                            LOG_PRINT("Connect to Server %s : %s", tokens[1].c_str(), tokens[2].c_str());
                            connectedFd = connect_to_server(tokens[1], tokens[2]);
                            cout << "connect returned" << endl;
                            if(connectedFd < 0)
                                perror("Connect failed");
                            FD_SET(connectedFd, &master_list);
                            /*if(connectedFd > head_socket)*/ head_socket = connectedFd;

                            ostringstream s;
                            s << "LOGIN " << port;
                            string buf(s.str());
                            s.clear(); // int sendall(int s, char *buf, int *len)
                            int len = buf.length();
                            if(sendall(connectedFd, (char*)buf.c_str(), &len) == -1) {
                                perror("failed to send the port number to the server");
                                return;
                            }
                            buf.clear();
                            fflush(stdout);

                        } else if(strcmp(tokens[0].c_str(), "REFRESH") == 0) {
                            cse4589_print_and_log("[%s:SUCCESS]\n", tokens[0].c_str());
                            LOG_PRINT("[%s:SUCCESS]\n", tokens[0].c_str());
                            string buf = std::string("REFRESH");
                            int len = buf.length();
                            if(sendall(connectedFd, (char*)buf.c_str(), &len) == -1) {
                                perror("failed to send the LOGOUT string to the server");
                                return;
                            }
                            _list.clear();
                            cout << "list size after truncate " << _list.size() << endl;
                            buf.clear();
                            fflush(stdout);

                        } else if(strcmp(tokens[0].c_str(), "SEND") == 0) {
                            LOG_PRINT("[%s:SUCCESS]\n", tokens[0].c_str());
                            cse4589_print_and_log("[%s:SUCCESS]\n", tokens[0].c_str());
                            if(getline(line, str, ' '))
                                tokens.push_back(str);
                            string _l = line.str();    // SEND <dest ip> <msg>
                            size_t pos = _l.find(" ");
                            string tmp = _l.substr(pos+1); // <destip> <msg>
                            pos = tmp.find(" ");
                            string msg = tmp.substr(pos+1); // <msg>
                           
                            ostringstream s;
                            s << tokens[0] << " " << tokens[1] << " " << msg;

                            cout << "Send message to client " << s.str() << endl;
                            string buf(s.str());
                            s.clear();
                            int len = buf.length();
                            if(sendall(connectedFd, (char*)buf.c_str(), &len) == -1) {
                                perror("failed to send the message from the client");
                                return;
                            }
                            buf.clear();
                            fflush(stdout);

                        } else if(strcmp(tokens[0].c_str(), "BROADCAST") == 0) {
                            cse4589_print_and_log("[%s:SUCCESS]\n", tokens[0].c_str());
                            LOG_PRINT("[%s:SUCCESS]\n", tokens[0].c_str());
                            ostringstream s;
                            s << tokens[0] << " " << tokens[1];

                            cout << "Send message to client " << s.str() << endl;
                            string buf(s.str());
                            s.clear();
                            int len = buf.length();
                            if(sendall(connectedFd, (char*)buf.c_str(), &len) == -1) {
                                perror("failed to send the messahe from the client");
                                return;
                            }
                            buf.clear();
                            fflush(stdout);
                        } else if(strcmp(tokens[0].c_str(), "BLOCK") == 0) {
                            cse4589_print_and_log("[%s:SUCCESS]\n", tokens[0].c_str());
                            ostringstream s;
                            s << tokens[0] << " " << tokens[1];
                            cout << "Block Client IP " << tokens[1];
                            string buf(s.str());
                            s.clear();
                            int len = buf.length();
                            if(sendall(connectedFd, (char*)buf.c_str(), &len) == -1) {
                                perror("failed to send the message from the client");
                                return;
                            }
                            buf.clear();
                            fflush(stdout);

                        } else if(strcmp(tokens[0].c_str(), "UNBLOCK") == 0) {
                            cse4589_print_and_log("[%s:SUCCESS]\n", tokens[0].c_str());
                            ostringstream s;
                            s << tokens[0] << " " << tokens[1];
                            cout << "Unblock CLient IP " << tokens[1];
                            string buf(s.str());
                            s.clear();
                            int len = buf.length();
                            if(sendall(connectedFd, (char*)buf.c_str(), &len) == -1) {
                                perror("failed to send the message from the client");
                                return;
                            }
                            buf.clear();
                            fflush(stdout);


                        } else if(strcmp(tokens[0].c_str(), "LOGOUT") == 0) {
                            cse4589_print_and_log("[%s:SUCCESS]\n", tokens[0].c_str());
                            
                            string buf = std::string("LOGOUT");
                            int len = buf.size();
                            if(sendall(connectedFd, (char*)buf.c_str(), &len) == -1) {
                                perror("failed to send the LOGOUT string to the server");
                                return;
                            }
                            buf.clear();
                            fflush(stdout);
                        } else if(strcmp(tokens[0].c_str(), "EXIT") == 0) {
                            cse4589_print_and_log("[%s:SUCCESS]\n", tokens[0].c_str());
                        } else {
                            cse4589_print_and_log("[%s:ERROR]\n", tokens[0].c_str());
                        }
                        LOG_PRINT("[%s:END]\n", tokens[0].c_str());
                        cse4589_print_and_log("[%s:END]\n", tokens[0].c_str());
                        cmd_input.clear();
                        line.clear();
                    } else if(sock_index == connectedFd) { /* Receive a response from server over connected socket*/
                        char buffer[BUFFER_SIZE];
                        memset(buffer, '\0', BUFFER_SIZE);
                        string str = "";
                        int len = BUFFER_SIZE;
                        if((recv(sock_index, buffer, len, 0)) <= 0) 
                        {
                            close(sock_index);
                            cout << "Remote Host terminated connection!" << endl;

                            /*Remove from watched list*/
                            FD_CLR(sock_index, &master_list);
                        } else {
                            str.clear();
                            str = std::string(buffer);
                            std::size_t pos = str.find(" ");
                            string cmd_response = str.substr(0, pos);
                            string msg = str.substr(pos + 1);
                            cout << "Length of message received from server " << msg.length() << endl; 
                            if(cmd_response == std::string("LOGIN")) {
                                //str = std::string(buffer);
                                cout << "Received from server.. for login " << endl << msg << endl;
                                stringstream s(msg);
                                string rec = "";
                                while(getline(s, rec, '$')) {
                                    if(-1 == presentInClientList(rec))
                                        _list.push_back(rec);
                                }
                                /*
                                if(-1 == presentInClientList(msg))
                                    _list.push_back(msg); */
                                fflush(stdout);
                            } else if(cmd_response == std::string("REFRESH")) {
                                //str = std::string(buffer);
                                _list.clear();
                                cout << "Received from server.. for refresh " << endl << msg << endl;
                                stringstream s(msg);
                                string rec = "";
                                while(getline(s, rec, '$')) {
                                    _list.push_back(rec);
                                }
                               fflush(stdout);
                            } else if(cmd_response == std::string("SEND") || cmd_response == std::string("BROADCAST")){ /* Receive message from the server sent by some client */
                                //str = std::string(buffer);
                                
                                cout << "Received from the server..for send " << endl << msg << endl;
                                size_t pos = msg.find(" "); // msg is <client ip> <msg>

                                string ip = msg.substr(0, pos);
                                string message = msg.substr(pos+1);
                               
                                LOG_PRINT("[%s:SUCCESS]\n", "RECEIVED");
                                LOG_PRINT("msg from:%s\n[msg]:%s\n", ip.c_str(), message.c_str());
                                LOG_PRINT("[%s:END]\n", "RECEIVED");
                        

                                cse4589_print_and_log("[%s:SUCCESS]\n", "RECEIVED");
                                cse4589_print_and_log("msg from:%s\n[msg]:%s\n", ip.c_str(), message.c_str());
                                cse4589_print_and_log("[%s:END]\n", "RECEIVED");
                                ip.clear();
                                message.clear();
                            } else { }
                            cmd_response.clear();
                            msg.clear();
                            fflush(stdout);

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
    LOG_PRINT("IP:%s\n", ip);
    cse4589_print_and_log("IP:%s\n", ip);
}
