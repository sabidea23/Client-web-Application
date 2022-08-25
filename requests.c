#include <stdlib.h>     /* exit, atoi, malloc, free */
#include <stdio.h>
#include <unistd.h>     /* read, write, close */
#include <string.h>     /* memcpy, memset */
#include <sys/socket.h> /* socket, connect */
#include <netinet/in.h> /* struct sockaddr_in, struct sockaddr */
#include <netdb.h>      /* struct hostent, gethostbyname */
#include <arpa/inet.h>
#include "helpers.h"
#include "requests.h"
#include "parson.h"

char *compute_get_request(char *host, char *url, char *query_params,
                                char **cookies, int cookies_count, 
                                char **jwt_tokens, int tokens_count) {
    char *message = calloc(BUFLEN, sizeof(char));
    char *line = calloc(LINELEN, sizeof(char));

    // Step 1: write the method name, URL, request params (if any) and protocol type
    if (query_params != NULL) 
        sprintf(line, "GET %s?%s HTTP/1.1", url, query_params);
    else 
        sprintf(line, "GET %s HTTP/1.1", url);

    compute_message(message, line);
    memset(line, 0, LINELEN);

    // Step 2: add the host
    sprintf(line, "Host: %s", host);
    compute_message(message, line);

    // Step 3 (optional): add headers and/or cookies, according to the protocol format
    if (cookies != NULL) {
        sprintf(line, "Cookie: ");
        
        for (int i = 0; i < cookies_count - 1; i++) {
            strcat(line, cookies[i]);
            strcat(line, ";");
        }
        strcat(line, cookies[cookies_count - 1]);
        compute_message(message, line);
    }

    // Step 4 (optional): add jwt_tokens
    if (jwt_tokens != NULL) {
        sprintf(line, "Authorization: Bearer ");
        for (int i = 0; i < tokens_count - 1; i++) {
            strcat(line, jwt_tokens[i]);
            strcat(line, ";");
        }

        strcat(line, jwt_tokens[tokens_count - 1]);
        compute_message(message, line);
    }

    // Step 5: add final new line
    compute_message(message, "");
    return message;
}

char *compute_post_request(char *host, char *url, char* content_type,
                           char **body_data, int body_data_fields_count, 
                           char **cookies, int cookies_count,
                           char **jwt_tokens, int tokens_count) {
    char *message = calloc(BUFLEN, sizeof(char));
    char *line = calloc(LINELEN, sizeof(char));
    char *body_data_buffer = calloc(LINELEN, sizeof(char));

    // Step 1: write the method name, URL and protocol type
    sprintf(line, "POST %s HTTP/1.1", url);
    compute_message(message, line);
    memset(line, 0, LINELEN);
    
    // Step 2: add the host
    sprintf(line, "Host: %s", host);
    compute_message(message, line);

    /* Step 3: add necessary headers (Content-Type and Content-Length are mandatory)
            in order to write Content-Length you must first compute the message size
    */
    sprintf(line, "Content-Type: %s", content_type);
    compute_message(message, line);

    /* The data is transformed into JSON objects, then into serialized 
    string, and copied in the buffer */
    JSON_Value *json_value = json_value_init_object();
    JSON_Object *json_object = json_value_get_object(json_value);
    char *serialized_string = NULL;

    if (body_data_fields_count == 2) {
        json_object_set_string(json_object, "username", body_data[0]);
        json_object_set_string(json_object, "password", body_data[1]);
        serialized_string = json_serialize_to_string_pretty(json_value); 
        strcpy(body_data_buffer, serialized_string);
        json_free_serialized_string(serialized_string);   

    } else if (body_data_fields_count == 5) {
        json_object_set_string(json_object, "title", body_data[0]);
        json_object_set_string(json_object, "author", body_data[1]); 
        json_object_set_string(json_object, "genre", body_data[2]);
        json_object_set_string(json_object, "page_count", body_data[3]);
        json_object_set_string(json_object, "publisher", body_data[4]);  

        serialized_string = json_serialize_to_string_pretty(json_value); 
        strcpy(body_data_buffer, serialized_string);
        json_free_serialized_string(serialized_string); 
    }
    json_value_free(json_value);

    int len = strlen(body_data_buffer);
    sprintf(line, "Content-Length: %d", len);
    compute_message(message, line);

    // Step 4 (optional): add cookies
    if (cookies != NULL) {
        sprintf(line, "Cookie: ");
        
        for (int i = 0; i < cookies_count - 1; i++) {
            strcat(line, cookies[i]);
            strcat(line, ";");
        }

        strcat(line, cookies[cookies_count - 1]);
        compute_message(message, line);
    }

    // Step 5: add jwt_tokens
    if (jwt_tokens != NULL) {
        sprintf(line, "Authorization: Bearer ");
        
        for(int i = 0; i < tokens_count - 1; i++) {
            strcat(line, jwt_tokens[i]);
            strcat(line, ";");
        }

        strcat(line, jwt_tokens[tokens_count - 1]);
        compute_message(message, line);
    }

    // Step 6: add new line at end of header
    compute_message(message, "");

    // Step 7: add the actual payload data
    memset(line, 0, LINELEN);
    compute_message(message, body_data_buffer);

    free(line);
    return message;
}

char *compute_delete_request(char *host, char *url, char *query_params,
                                char **cookies, int cookies_count, 
                                char **jwt_tokens, int tokens_count) {
    char *message = calloc(BUFLEN, sizeof(char));
    char *line = calloc(LINELEN, sizeof(char));

    // Step 1: write the method name, URL, request params (if any) and protocol type
    if (query_params != NULL) {
        sprintf(line, "DELETE %s?%s HTTP/1.1", url, query_params);
    } else {
        sprintf(line, "DELETE %s HTTP/1.1", url);
    }

    compute_message(message, line);

    // Step 2: add the host
    sprintf(line, "Host: %s", host);
    compute_message(message, line);

    // Step 3 (optional): add headers and/or cookies, according to the protocol format
    if (cookies != NULL) {
        sprintf(line, "Cookie: ");
        
        for (int i = 0; i < cookies_count - 1; i++) {
            strcat(line, cookies[i]);
            strcat(line, ";");
        }
        strcat(line, cookies[cookies_count - 1]);
        compute_message(message, line);
        memset(line, 0, LINELEN);
    }

    // Step 4: add JWT token
    if (jwt_tokens != NULL) {
        sprintf(line, "Authorization: Bearer ");
        
        for (int i = 0; i < tokens_count - 1; i++) {
            strcat(line, jwt_tokens[i]);
            strcat(line, ";");
        }
        strcat(line, jwt_tokens[tokens_count - 1]);
        compute_message(message, line);
    }

    // Step 5: add final new line
    compute_message(message, "");
    return message;
}