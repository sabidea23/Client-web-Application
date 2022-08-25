/* Dinu Andreea Sabina- 322CB */
#include <stdio.h>      /* printf, sprintf */
#include <stdlib.h>     /* exit, atoi, malloc, free */
#include <unistd.h>     /* read, write, close */
#include <string.h>     /* memcpy, memset */
#include <sys/socket.h> /* socket, connect */
#include <netinet/in.h> /* struct sockaddr_in, struct sockaddr */
#include <netdb.h>      /* struct hostent, gethostbyname */
#include <arpa/inet.h>
#include "helpers.h"
#include "requests.h"
#include "parson.h"
#define MAX_DATA_LENGTH 50
#define MAX_COOKIE_LENGTH 150
#define MAX_URL_LENGTH 150
#define MAX_ID_LENGTH 50

/* Allocate memory for the body data */
char** alloc_payload(int payload_fields_count, int data_size) {
    char **payload = (char **)malloc(payload_fields_count * sizeof(char*));
    if (!payload)
        return NULL;

    for (int i = 0; i < payload_fields_count; i++) {
        payload[i] = (char *)malloc(data_size * sizeof(char));
        if (!payload[i]) {
            free(payload);
            return NULL;
        }
    } 
    return payload;
}

/* Free the memory allocated for the body data of a request */
void free_payload(char ***payload, int payload_fields_count) {
    for (int i = 0; i < payload_fields_count; i++) {
        free((*payload)[i]);
    }
    free(*payload);
}

/* Receive login or register instructions from stdin 
and make a post request with the data from the stdin 
(username and password) */
char* access_account(char * command, int sockfd) {
    /* Alloc memory for the body data */
    int payload_fields_count = 2;
    char **payload = alloc_payload(payload_fields_count, MAX_DATA_LENGTH);
    if (!payload)
        return NULL;

    /* Read username from stdin */
    printf("username=");
    scanf("%s", payload[0]);
    
    /* Read password from stdin */
    printf("password=");
    scanf("%s", payload[1]);

    /* Sent a POST request with the coresponding URL */
    char *message;
    if (strncmp(command, "login", 5) == 0)
        message = compute_post_request("34.241.4.235", "/api/v1/tema/auth/login", 
                                "application/json", payload, 2, NULL, 0, NULL, 0);

    else if (strncmp(command, "register", 8) == 0) 
        message = compute_post_request("34.241.4.235", "/api/v1/tema/auth/register", 
                                "application/json", payload, 2, NULL, 0, NULL, 0);
  
    /* Send the POST request to the server */
    send_to_server(sockfd, message);
    free(message);

    /* Receive and print the POST reply from server */
    char *response = receive_from_server(sockfd);
    printf("%s\n", response);

    /* Free the memory allocated for payload */
    free_payload(&payload, payload_fields_count);

    return response;
}

/* Receive a login instruction, make a POST request and get a reply, 
from which exracts the cookie and return it */
char* login_command(char *cookie,  char* command, int sockfd, int *already_logged) { 
    char* response = access_account(command, sockfd);

    if (!strstr(response, "error")) {
        char *token = strtok(response, "\r\n ");
    
        while (token != NULL) {
            if (strcmp(token, "Set-Cookie:") == 0) {
                *already_logged = 1;
                if (!cookie) {
                    cookie = (char *)malloc(MAX_COOKIE_LENGTH);
                    if (!cookie)
                    return NULL;
                }

                token = strtok(NULL, "\r\n ");
                strcpy(cookie, token);
                strcat(cookie, " ");

                token = strtok(NULL, "\r\n ");
                strcat(cookie, token);
                strcat(cookie, " ");

                token = strtok(NULL, "\r\n ");
                strcat(cookie, token);
                strcat(cookie, "\n");
                break;
            }
            token = strtok(NULL, "\r\n ");
        }
    }
    return cookie;
}

/* Extract a JWT token from a reply using parson library 
for parsing JSONS */
char* extract_jwt_token(char *response) {
    char* jwt_token = (char *)malloc(BUFLEN);
    if (!jwt_token)
        return NULL;
        
    char *token = strtok(response, "\n");

    /* Split the reply in tokens and the last one is 
    the JWT token */
    while (token != NULL) {
        strcpy(jwt_token, token);
        token = strtok(NULL, "\n");
    }

    token = (char *)malloc(BUFLEN);
    if (!token)
        return NULL;
    strcpy(token, "token");

    /* Parse the JWT token in a JSON value, then into a 
    JSON object, then it is converted into a string and it
    copies the JWT token into it */
    JSON_Value *json_value = json_parse_string(jwt_token);
    JSON_Object *json_object = json_value_get_object(json_value);
    strcpy(jwt_token, json_object_get_string (json_object, token));

    json_value_free(json_value);
    free(token);

    return jwt_token;
}

/* Compute a GET request and receive a cookie is the user was
already logged in, It returns the JWT token extracted from the response */
char* enter_library(char *cookie, int sockfd, int *already_logged) {
    char *message;

    /* If the user is not logged, compute a GET request without cookie */
    if (*already_logged == 1) {
        char **cookies = alloc_payload(1, BUFLEN);
        if (!cookies)
            return NULL;
        strcpy(cookies[0], cookie);

        message = compute_get_request("34.241.4.235", "/api/v1/tema/library/access",
                                     NULL, cookies, 1, NULL, 0);
      
        free_payload(&cookies,1);

    } else 
        message = compute_get_request("34.241.4.235", "/api/v1/tema/library/access",
                            NULL, NULL, 0, NULL, 0);
 
    /* Make a GET request and get a response and print it */
    send_to_server(sockfd, message);
    char *response = receive_from_server(sockfd);

    /* If the user is logged in, extract the JWT token */
    char* jwt_token = NULL;
    printf("%s\n", response);
    if (*already_logged == 1)
        jwt_token = extract_jwt_token(response);

    free(response);
    free(message);
    return jwt_token;
}

/* Compute a GET request with the JWT token,
in order to show all the books from the system, when we receive
the command "get_books" */
void get_books(char* jwt_token, int sockfd) {
    char *message;

    /* If the token is not null, compute the request with the JWT token */
    if (jwt_token != NULL) {
        /* Copy the token in the first element of the array */
        char **jwt_tokens = alloc_payload(1, strlen(jwt_token));
        if (!jwt_tokens)
            return;
        strcpy(jwt_tokens[0], jwt_token);

        message = compute_get_request("34.118.48.238", "/api/v1/tema/library/books",
                                       NULL, NULL, 0, jwt_tokens, 1);

        free_payload(&jwt_tokens, 1);

    /* Else, compute the request without the JWT token */
    } else 
        message = compute_get_request("34.118.48.238", "/api/v1/tema/library/books",
                                       NULL, NULL, 0, NULL, 0);

    /* Send the request to server and print the response */
    send_to_server(sockfd, message);
    char *response = receive_from_server(sockfd);

    printf("%s\n", response);
    free(response);
    free(message);
}

/* Receive a get_book command or a delete_books command and 
make a GET request */
void book_operation(char* command, int sockfd, char* jwt_token) {
    char *message;

    printf("id=");
    char *id = (char *)malloc(MAX_ID_LENGTH);
    if (!id)
        return;
    scanf("%s", id);

    char *url = (char *)malloc(MAX_URL_LENGTH);
    if (!url)
        return;
    strcpy(url,  "/api/v1/tema/library/books/");
    strcat(url, id);

    /* If the JWT is not empty, make the request using it */
    if (jwt_token != NULL) {
        /* Copy the token in the first element of the array */
        char **jwt_tokens = alloc_payload(1, strlen(jwt_token));
        if (!jwt_tokens)
            return;
        strcpy(jwt_tokens[0], jwt_token);

        if (strncmp(command, "delete_book", 11 ) == 0) 
            message = compute_delete_request("34.241.4.235", url,
                                       NULL, NULL, 0, jwt_tokens, 1);
        else if (strncmp(command, "get_book", 8) == 0) 
           message = compute_get_request("34.241.4.235", url,
                                       NULL, NULL, 0, jwt_tokens, 1);
  
        free_payload(&jwt_tokens, 1);

    } else {
        if (strncmp(command, "delete_book", 11 ) == 0) 
            message = compute_delete_request("34.241.4.235", url,
                            NULL, NULL, 0, NULL, 0);        

        else if (strncmp(command, "get_book", 8) == 0) 
            message = compute_get_request("34.241.4.235", url,
                                       NULL, NULL, 0, NULL, 0);
    }

    /* Sends the request to the server, receives the response and print it */
    send_to_server(sockfd, message);
    char *response = receive_from_server(sockfd);
    printf("%s\n", response);

    free(message);
    free(response);
    free(id);
    free(url);
}

/* Read the information about the book from STDIN */
void read_new_book(char **payload) {
    printf("title=");
    scanf("%s", payload[0]);

    printf("author=");
    scanf("%s", payload[1]);

    printf("genre=");
    scanf("%s", payload[2]);
    
    printf("page_count=");
    scanf("%s", payload[3]);

    printf("publisher=");
    scanf("%s", payload[4]);
}

/* Add a new book in the library by making a POST request */
void add_book(char* jwt_token, int sockfd) {
    char *message;

    /* Compute a POST request without a JWT token */
    if (!jwt_token) {
        message = compute_post_request("34.241.4.235", "/api/v1/tema/library/books",
                                        "application/json", NULL, 0, NULL, 0,
                                        NULL, 0);
    } else {
        int payload_fields_count = 5;
        char **payload = alloc_payload(payload_fields_count, MAX_DATA_LENGTH);
        if (!payload)
            return;

        /* Read the information about the book from STDIN */
        read_new_book(payload);

        char **jwt_tokens = alloc_payload(1, strlen(jwt_token));
        if (!jwt_tokens)
            return;
        strcpy(jwt_tokens[0], jwt_token);

        message = compute_post_request("34.241.4.235", "/api/v1/tema/library/books",
                                    "application/json", payload, 5, NULL, 0,
                                    jwt_tokens, 1);

        free_payload(&payload, payload_fields_count);
        free_payload(&jwt_tokens, 1);
    }

    /* Send the POST request, receive the response and print it */
    send_to_server(sockfd, message);
    char *response = receive_from_server(sockfd);
    printf("%s\n", response);

    free(message);
    free(response);
}

/* Make the logout for a user by making a GET request */
void logout_command(int sockfd, char* cookie, int *already_logged) {
    char *message;

    if (*already_logged == 1) {
        /* Copy the cookie in the first element of the array */
        char **cookies = alloc_payload(1, MAX_COOKIE_LENGTH);
        if (!cookies)
            return;
        strcpy(cookies[0], cookie);

        message = compute_get_request("34.241.4.235", "/api/v1/tema/auth/logout",
                                    NULL, cookies, 1, NULL, 0);
        free_payload(&cookies, 1);

    /* Compute the request without cookie if the user is not logged */
    } else 
        message = compute_get_request("34.241.4.235", "/api/v1/tema/auth/logout",
                                    NULL, NULL, 0, NULL, 0);

    /* Send the GET request to the  server, receive a response and print it */
    send_to_server(sockfd, message);
    char *response = receive_from_server(sockfd);
    printf("%s\n", response);

    /* The user isn't logged anymore */
    if (*already_logged == 1) 
        *already_logged = 0;
    free(response);
    free(message);
}

/* Free the memory allocated for a string if it not empty */
void free_not_empty(char **string) {
    if (*string != NULL) {
        free(*string);
        *string = NULL;
    }
}

int main(int argc, char *argv[]) {
    int already_logged = 0;
    char *response = NULL, *cookie = NULL, *jwt_token = NULL;
    printf("Possible instructions: register, login, logout, enter_library, get_book, get_books, add_book, exit, delete_book\n");

    while (1) {
        /* Read instuctions from STDIN */
        char buf[BUFLEN];
        scanf("%s", buf);

        if (strncmp(buf, "exit", 4) == 0) 
            return 0;

        /* Create a new socket */
        int sockfd = open_connection("34.241.4.235", 8080, AF_INET, SOCK_STREAM, 0);

        if (strncmp(buf, "register", 8) == 0) {
            response = access_account(buf, sockfd);
            free_not_empty(&response);

        } else if (strncmp(buf, "login", 5) == 0) {
            if (already_logged == 1) {
                printf("You are already logged into your account\n");
                continue;
            }
            cookie = login_command(cookie, buf, sockfd, &already_logged);

        } else if (strncmp(buf, "enter_library", 13) == 0) {
            if (already_logged == 0) {
                printf("You need to login first\n");
                continue;
            }
            jwt_token = enter_library(cookie, sockfd, &already_logged);

        } else if (strncmp(buf, "get_books", 9) == 0) {
            if (already_logged == 0) {
                printf("You need to login first\n");
                continue;
            }
            get_books(jwt_token, sockfd);

        } else if (strncmp(buf, "get_book", 8) == 0) {
            if (already_logged == 0) {
                printf("You need to login first\n");
                continue;
            }
            book_operation(buf, sockfd, jwt_token);

        } else if (strncmp(buf, "add_book", 8) == 0) {
            if (already_logged == 0) {
                printf("You need to login first\n");
                continue;
            }
            add_book(jwt_token, sockfd);

        } else if (strncmp(buf, "delete_book", 11) == 0) {
            if (already_logged == 0) {
                printf("You need to login first\n");
                continue;
            }
            book_operation(buf, sockfd, jwt_token);

        } else if (strncmp(buf, "logout", 6) == 0) {
            logout_command(sockfd, cookie, &already_logged);
            free_not_empty(&cookie);
            free_not_empty(&jwt_token);

        } else 
            printf("Invalid command\n");
    
        /* Close the socket */
        close_connection(sockfd);
    }

    free_not_empty(&cookie);
    free_not_empty(&jwt_token);
    free_not_empty(&response);

    return 0;
}