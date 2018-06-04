#ifdef WIN32
#include <windows.h>
#include <winsock2.h>
#else
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#endif
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "microhttpd.h"

#define HTTPD_PORT (8888)
#define URL_LEN_MAX		(1024)

#define SERVERKEYFILE "httpd.key"
#define SERVERCERTFILE "httpd.pem"

const char *errorpage =
"{\"protocol\": \"https\",\"domain\" : \"127.0.0.1\",\"port\" : 8888,\"token\" : \"01_42423423423432423423aaaaf\"}";

#define PATH_BUF_LEN    (256)
#define MODE_BUF_LEN	(16)
#ifdef WIN32
static int UTF8ToUnicode(const char* str_utf8, wchar_t* str_unicode)
{
	DWORD len_unicode = MultiByteToWideChar(CP_UTF8, 0, str_utf8, -1, NULL, 0);
	TCHAR *pwText = (TCHAR *)malloc(sizeof(TCHAR)* len_unicode);
	if (NULL == pwText)
	{
		return -1;
	}
	MultiByteToWideChar(CP_UTF8, 0, str_utf8, -1, pwText, len_unicode);
	wcscpy(str_unicode, pwText);
	free(pwText);
	return 0;
}
#endif
static FILE * file_open(const char *name, const char *mode)
{
#ifdef WIN32
	wchar_t wmode[sizeof(wchar_t)* MODE_BUF_LEN];
	wchar_t wname[sizeof(wchar_t)* PATH_BUF_LEN];
	if (UTF8ToUnicode(mode, wmode) == -1)
	{
		return NULL;
	}
	if (UTF8ToUnicode(name, wname) == -1)
	{
		return NULL;
	}
	return _wfopen(wname, wmode);
#else
	return fopen(name, mode);
#endif
}

#define METHOD_GET           0
#define METHOD_POST          1
#define METHOD_PUT           2
#define METHOD_DELETE        3
#define METHOD_OPTIONS		 4

struct connection_info_struct
{
	struct MHD_Connection *connection;
	int   request_method;
	char *request_url;
	int   request_body_len;
	char *request_body;
};

int send_response(struct MHD_Connection *connection, int answercode, const char *answerstring)
{
	int ret = -1;
	struct MHD_Response *response =
		MHD_create_response_from_buffer(strlen(answerstring), (void *)answerstring, MHD_RESPMEM_MUST_COPY);
	if (!response)
		return MHD_NO;
	MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_TYPE, "application/json");
	MHD_add_response_header(response, MHD_HTTP_HEADER_ACCEPT_CHARSET, "utf-8");
	MHD_add_response_header(response, MHD_HTTP_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN, "*");
	MHD_add_response_header(response, "Access-Control-Allow-Credentials", "true");
	MHD_add_response_header(response, "Access-Control-Allow-Methods", "OPTIONS, POST, GET, PUT, DELETE");
	MHD_add_response_header(response, "Access-Control-Allow-Headers", "active-key, Content-Type");
	ret = MHD_queue_response(connection, answercode, response);
	MHD_destroy_response(response);
	return ret;
}

//MHD_RequestCompletedCallback
void request_completed(void *cls, struct MHD_Connection *connection, void **con_cls, enum MHD_RequestTerminationCode toe)
{
	struct connection_info_struct *con_info = (struct connection_info_struct *)*con_cls;
	if (con_info != NULL)
	{
		if (con_info->request_url != NULL)
		{
			free(con_info->request_url);
		}
		if (con_info->request_body != NULL)
		{
			free(con_info->request_body);
		}
		free(con_info);
		*con_cls = NULL;
	}
}

//MHD_KeyValueIterator
static int iterator_keyValue(void *cls, enum MHD_ValueKind kind, const char *key, const char *value)
{
	if (MHD_HEADER_KIND == kind)
	{
		if (strcmp(key, "accept-key") == 0)
		{
			char *acceptKEY = (char *)cls;
			strcpy(acceptKEY, value);
		}
	}
	return MHD_YES;
}

int authentication_client(struct MHD_Connection *connection)
{
	char acceptKEY[128];
	memset(acceptKEY, 0, sizeof(acceptKEY));
	MHD_get_connection_values(connection, MHD_HEADER_KIND, iterator_keyValue, acceptKEY);
	printf("accept KEY:%s\n", acceptKEY);
	return 0;
}

//process request
int ServeHTTP(struct connection_info_struct *con_info) 
{
	printf("process:\n");
	printf("	method:%d\n", con_info->request_method);
	printf("	url:%s\n", con_info->request_url);
	if (con_info->request_method != METHOD_GET)
	{
		printf("	request_body_len:%d\n", con_info->request_body_len);
		printf("	request_body:%s\n", con_info->request_body);
	}
	return send_response(con_info->connection, MHD_HTTP_NOT_FOUND, errorpage);
}

int answer_to_connection(void *cls, struct MHD_Connection *connection, const char *url, const char *method, const char *version, const char *upload_data, size_t *upload_data_size, void **con_cls)
{
	printf("New %s request: %s, using version %s\n", method, url, version);
	if (NULL == *con_cls)
	{
		struct connection_info_struct *con_info = (struct connection_info_struct *)malloc(sizeof (struct connection_info_struct));
		if (NULL == con_info)
		{
			return MHD_NO;
		}
		con_info->connection = connection;
		con_info->request_method = -1;
		con_info->request_url = (char *)malloc(sizeof(char)* URL_LEN_MAX);
		con_info->request_body_len = 0;
		con_info->request_body = NULL;// (char *)malloc(sizeof(char)* BODY_LEN_MAX);
		if (NULL == con_info->request_url)
		{
			free(con_info);
			return MHD_NO;
		}
		memset(con_info->request_url, 0, URL_LEN_MAX);
		strncpy(con_info->request_url, url, strlen(url));
		con_info->request_url[URL_LEN_MAX - 1] = '\0';
		if (strcmp(method, MHD_HTTP_METHOD_DELETE) == 0)
		{
			int content_len = 0;
			const char *param = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, MHD_HTTP_HEADER_CONTENT_LENGTH);
			if (param != NULL && strcmp(param, "") != 0)
			{
				content_len = atoi(param);
			}
			con_info->request_method = METHOD_DELETE;
			con_info->request_body = (char *)malloc(sizeof(char)* (content_len + 1));
			if (NULL == con_info->request_body)
			{
				free(con_info->request_url);
				free(con_info);
				return MHD_NO;
			}
			memset(con_info->request_body, 0, content_len + 1);
		}
		else if (strcmp(method, MHD_HTTP_METHOD_PUT) == 0)
		{
			const char *param = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, MHD_HTTP_HEADER_CONTENT_LENGTH);
			int content_len = atoi(param);
			con_info->request_method = METHOD_PUT;
			con_info->request_body = (char *)malloc(sizeof(char)* (content_len + 1));
			if (NULL == con_info->request_body)
			{
				free(con_info->request_url);
				free(con_info);
				return MHD_NO;
			}
			memset(con_info->request_body, 0, content_len + 1);
		}
		else if (strcmp(method, MHD_HTTP_METHOD_POST) == 0)
		{
			const char *param = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, MHD_HTTP_HEADER_CONTENT_LENGTH);
			int content_len = atoi(param);
			con_info->request_method = METHOD_POST;
			con_info->request_body = (char *)malloc(sizeof(char)* (content_len + 1));
			if (NULL == con_info->request_body)
			{
				free(con_info->request_url);
				free(con_info);
				return MHD_NO;
			}
			memset(con_info->request_body, 0, content_len + 1);
		}
		else if (strcmp(method, MHD_HTTP_METHOD_GET) == 0)
		{
			con_info->request_method = METHOD_GET;
		}
		else if (strcmp(method, MHD_HTTP_METHOD_OPTIONS) == 0)
		{
			con_info->request_method = METHOD_OPTIONS;
		}
		*con_cls = (void *)con_info;
		return MHD_YES;
	}
	struct connection_info_struct *con_info = (struct connection_info_struct *)(*con_cls);
	if (*upload_data_size != 0)
	{
		memcpy(con_info->request_body + con_info->request_body_len, upload_data, *upload_data_size);
		con_info->request_body_len += *upload_data_size;
		con_info->request_body[con_info->request_body_len] = '\0';
		*upload_data_size = 0;
		return MHD_YES;
	}
	ServeHTTP(con_info);
	return MHD_YES;
}

long get_file_size(const char *filename)
{
	FILE *fp;
	fp = file_open(filename, "rb");
	if (fp)
	{
		long size;
		if ((0 != fseek(fp, 0, SEEK_END)) || (-1 == (size = ftell(fp))))
			size = 0;
		fclose(fp);
		return size;
	}
	else
		return 0;
}

char *load_file(const char *filename)
{
	FILE *fp;
	char *buffer;
	long size;
	size = get_file_size(filename);
	if (0 == size)
		return NULL;
	fp = file_open(filename, "rb");
	if (!fp)
		return NULL;
	buffer = (char *)malloc(sizeof(char)* (size + 1));
	if (!buffer)
	{
		fclose(fp);
		return NULL;
	}
	buffer[size] = '\0';
	if (size != fread(buffer, 1, size, fp))
	{
		free(buffer);
		buffer = NULL;
	}
	fclose(fp);
	return buffer;
}

int main(void)
{
	struct MHD_Daemon *daemon;
	char *key_pem;
	char *cert_pem;
	key_pem = load_file(SERVERKEYFILE);
	cert_pem = load_file(SERVERCERTFILE);
	if ((key_pem == NULL) || (cert_pem == NULL))
	{
		printf("The key/certificate files could not be read.\n");
		return 1;
	}
	daemon = MHD_start_daemon(MHD_USE_THREAD_PER_CONNECTION | MHD_USE_SSL,
		HTTPD_PORT,
		NULL, NULL,
		&answer_to_connection, NULL,
		MHD_OPTION_HTTPS_MEM_KEY, key_pem,
		MHD_OPTION_HTTPS_MEM_CERT, cert_pem,
		MHD_OPTION_NOTIFY_COMPLETED, request_completed, NULL,
		MHD_OPTION_END);
	if (NULL == daemon)
	{
		printf("%s\n", cert_pem);
		free(key_pem);
		free(cert_pem);
		key_pem = NULL;
		cert_pem = NULL;
		return -1;
	}
	(void)getchar();
	MHD_stop_daemon(daemon);
	free(key_pem);
	free(cert_pem);
	return 0;
}