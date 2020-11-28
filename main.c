#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include "telegram_bot.h"

int	init_socket(int port, in_addr_t in_addr)
{
	int			s;
	struct sockaddr_in	addr;

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl(in_addr);

	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0){
		perror("Unable to create socket");
		exit(EXIT_FAILURE);
	}

	if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		perror("Unable to bind");
		exit(EXIT_FAILURE);
	}

	return s;
}

void	init_openssl(){
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();
}

void	cleanup_openssl(){
	EVP_cleanup();
}

SSL_CTX	*create_context(){
	const SSL_METHOD	*method;
	SSL_CTX			*ctx;

	method = TLS_server_method();

	ctx = SSL_CTX_new(method);
	if (!ctx) {
		perror("Unable to create SSL context");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	
	return ctx;
}

void	configure_context(SSL_CTX *ctx){
	SSL_CTX_set_ecdh_auto(ctx, 1);

	if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
}

int	create_soc_and_connect(){
	int			soc;
	struct hostent		*server;
	struct sockaddr_in	serv_addr;

	int port = PORT;
	char host[] = "api.telegram.org";

	soc = socket(AF_INET, SOCK_STREAM, 0);
	if (soc < 0){
		perror("Error opening socket");
		exit(0);
	}
	if (!(server = gethostbyname(host))){
		perror("Error resolving host");
		exit(0);
	}
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	memcpy(&serv_addr.sin_addr.s_addr, server->h_addr, server->h_length);
	serv_addr.sin_port = htons(port);
	if (connect(soc, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
		perror("Error connecting");
		exit(0);
	}
	return(soc);
}

void	send_message(int chat_id, char *msg){
	int	soc;
	
	char token[] = TOKEN;
	char header[] = "GET /bot%s/sendMessage?%s HTTP/1.1\r\nHost: api.telegram.org\r\n\n\n";
	char template[] = "chat_id=%d&text=%s";
	char body[strlen(template) + strlen(msg) + 16];
	memset(body, 0, strlen(template) + strlen(msg) + 16);
	sprintf(body, template, chat_id, msg);
	char request[strlen(header) + strlen(token) + strlen(body)];
	memset(request, 0, strlen(header) + strlen(token) + strlen(body));
	sprintf(request, header, token, body);
	printf("Request:\n==================\n%s\n==================\n", request);

	soc = create_soc_and_connect();
	SSL_CTX *sslctx = SSL_CTX_new(TLS_client_method());
	SSL *cSSL = SSL_new(sslctx);
	SSL_set_fd(cSSL, soc);
	printf("SSL_connect return value: %d\n", SSL_connect(cSSL));
	printf("SSL_write return value: %d\n", SSL_write(cSSL, request, (int)strlen(request)));

	char str[1024];
	SSL_read(cSSL, str, 1024);
	printf("str:\n================\n%s\n", str);
	SSL_clear(cSSL);
	SSL_CTX_free(sslctx);
	close(soc);
}

void	process_msg(char *msg, int chat_id){
	if (!strcmp(msg, "/help"))
		send_message(chat_id, "Это бот для организации встреч квир людей. Хотите участвовать?");
	else if (!strcmp(msg, "/start"))
		send_message(chat_id, "What do you want to start?");
	else
		send_message(chat_id, msg);
	return ;
}

int	main(int argc, char **argv){
	int 	sock;
	SSL_CTX	*ctx;

	init_openssl();
	ctx = create_context();

	configure_context(ctx);

	sock = init_socket(PORT, INADDR_ANY);

	if (listen(sock, 5) < 0) {
		perror("Unable to listen");
		exit(EXIT_FAILURE);
	}

	while(1){
		struct sockaddr_in	addr;
		uint			len = sizeof(addr);
		SSL			*ssl;

		int client = accept(sock, (struct sockaddr *)&addr, &len);
		if (client < 0){
			perror("Unable to accept");
			exit(EXIT_FAILURE);
		}

		ssl = SSL_new(ctx);
		SSL_set_fd(ssl, client);
		if (SSL_accept(ssl) <= 0){
			ERR_print_errors_fp(stderr);
		}
		int pid = fork();
		if (pid != 0){
			SSL_clear(ssl);
			close(client);
			continue ;
		}

		char response[] = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n";
		char header[1024];
		memset(header, 0, 1024);
		int s = 0;
		int n = 0;
		while (strcmp(header + s - strlen("\r\n\r\n"), "\r\n\r\n")){
			n = SSL_read(ssl, header + s, 1);
			s += n;
		}
		SSL_write(ssl, response, strlen(response));
		printf("Header:\n=========================\n%s\n=========================\n", header);
		if (!(strstr(header, "POST /queer HTTP/1.1\r\n"))){
			SSL_clear(ssl);
			close(client);
			exit(0);
		}
		
		if (!(strstr(header, "Content-Type: application/json"))){
			SSL_clear(ssl);
			close(client);
			exit(0);
		}

		int leng = atoi(strstr(header, "Content-Length: ") + strlen("Content-Length: "));
		char body[leng + 2];
		memset(body, 0, leng + 2);
		n = 0;
		s = 0;
		while (leng - s > 0) {
			n = SSL_read(ssl, body + s, leng - s);
			s += n;
		}
		printf("Body:\n====================\n%s\n=================\n", body);
		SSL_clear(ssl);
		SSL_free(ssl);
		close(client);
		int chat_id = atoi(strstr(body, "\"chat\":{\"id\":") + strlen("\"chat\":{\"id\":"));
		char *text_begin;
		char *text_end;
		char *text;

		text_begin = strstr(body, "\"text\":\"") + strlen("\"text\":\"");
		text_end = strstr(text_begin, "\"");

		text = (char *)calloc(text_end - text_begin + 2, sizeof(char));
		text = strncpy(text, text_begin, text_end - text_begin);
		printf("text: %s\n", text);
		printf("chat_id: %d\n", chat_id);
		process_msg(text, chat_id);
//		SSL_shutdown(ssl);
//		SSL_free(ssl);
//		close(client);
		exit(0);
	}

	close(sock);
	SSL_CTX_free(ctx);
	cleanup_openssl();
}
