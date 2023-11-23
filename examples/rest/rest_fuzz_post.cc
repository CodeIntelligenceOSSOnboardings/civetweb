#include <unistd.h>
#include "civetweb.h"
#include "cJSON.h"

#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>

#define HOST "localhost"
#define PORT "8089"
#define VULN_ENDPOINT "/fuzz"

struct mg_callbacks callbacks;
struct mg_context *ctx;

int server_started = false;
static int VulnEndpointHandler(struct mg_connection *conn, void *cbdata);


static int
VulnEndpointHandler(struct mg_connection *conn, void *cbdata)
{
	const struct mg_request_info *ri = mg_get_request_info(conn);

	// NOTE: BUG entry point
	if (strcmp(ri->request_method, "POST") == 0) {

	
		char buffer[1024];
		int dlen = mg_read(conn, buffer, sizeof(buffer) - 1);
		cJSON *obj, *elem;

		if ((dlen < 1) || (dlen >= sizeof(buffer))) {
			mg_send_http_error(conn, 400, "%s", "No request body data");
			fprintf(stderr, "No request body\n");
			return 400;
		}

		buffer[dlen] = 0;

		obj = cJSON_Parse(buffer);
		if (obj == NULL) {
			const char *error_ptr = cJSON_GetErrorPtr();
			if (error_ptr != NULL)
			{
			}
			mg_send_http_error(conn, 400, "%s", "Invalid request body data");
			cJSON_Delete(obj);
			return 400;
		}

		cJSON *profile = NULL;
		profile = cJSON_GetObjectItemCaseSensitive(obj, "profile");
		
		if (cJSON_IsString(profile) && (strncmp(profile->valuestring, "fuzz", 4) == 0))
		{
			//fprintf(stderr, "profile=%s\n", profile->valuestring);
			char buffer[64]; // This is a small local buffer

			// Vulnerability: We are copying the entire query_string into the
			// local buffer without checking its length
			strcpy(buffer, profile->valuestring);
			mg_send_http_ok(conn, "text/plain", strlen(buffer));
			mg_write(conn, buffer, strlen(buffer));
			cJSON_Delete(obj);
			return 200;
		}

		mg_send_http_error(conn,
							400,
							"Invalid json value for profile key: %s\n",
							profile);
		cJSON_Delete(obj);
		return 400;
	}
	mg_send_http_error(conn, 405, "Only POST method supported");
	return 405;
}


int
setup_server()
{
	const char *options[] = {"listening_ports",
	                         PORT,
	                         "request_timeout_ms",
	                         "100000",
	                         "error_log_file",
	                         "error.log",
	                         0};

	/* Init libcivetweb. */
	mg_init_library(0);

	/* Start CivetWeb web server */
	ctx = mg_start(&callbacks, 0, options);

	if (ctx == NULL) {
		fprintf(stderr, "Cannot start CivetWeb - mg_start failed.\n");
		return EXIT_FAILURE;
	}

	mg_set_request_handler(ctx, VULN_ENDPOINT, VulnEndpointHandler, 0);

	printf("Fuzz example: http://%s:%s%s\n", HOST, PORT, VULN_ENDPOINT);
	return 0;
}


FUZZ_TEST(const uint8_t *data, size_t size)
{
	if (!server_started) {
		setup_server();
		server_started = true;
	}

	char errbuf[256] = {0};
	struct mg_connection *client =
	    mg_connect_client(HOST, atoi(PORT), 0, errbuf, sizeof(errbuf));

	if (client == NULL) {
		fprintf(stderr, "Cannot connect client: %s\n", errbuf);
		return;
	}

	FuzzedDataProvider fuzzed_data(data, size);
	char* method = "POST";
	char* path = "/fuzz";
	
	std::string input1 = fuzzed_data.ConsumeRemainingBytesAsString();
	char * val1 = &input1[0];

	char * content;
	const char * json_template = 
		"{ \
			\"profile\":\"%s\", \
			\"friends\": [ \
				{ \
					\"name\": \"bob\", \
					\"age\": \"18\"	\
				}, \
				{ \
					\"name\": \"alice\", \
					\"age\": \"21\"	\
				} \
			] \
		}";


	int content_length = snprintf(NULL, 0, json_template, val1);
	content = (char*) malloc(content_length +1);
	snprintf(content, content_length +1, json_template, val1);

	mg_printf(client,
	          "%s %s HTTP/1.1\r\n",
	          method,
			  path
	          );
	mg_printf(client, "Host: %s\r\n", HOST);
	mg_printf(client, "Content-Type: application/json\r\n");
	mg_printf(client, "Content-Length: %d\r\n\r\n", content_length);
	mg_printf(client, content);

	mg_get_response(client, errbuf, sizeof(errbuf), -1);
	mg_close_connection(client);

	free(content);

	return;
}
