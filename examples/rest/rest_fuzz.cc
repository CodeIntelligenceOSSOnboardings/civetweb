#include <unistd.h>
#include "civetweb.h"

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
	char path1[1024], path2[1024];
	const struct mg_request_info *ri = mg_get_request_info(conn);
	struct mg_match_context mcx;
	mcx.case_sensitive = 0;
	mg_match(VULN_ENDPOINT, ri->local_uri, &mcx);
	memcpy(path1, mcx.match[0].str, mcx.match[0].len);
	path1[mcx.match[0].len] = 0;
	memcpy(path2, mcx.match[1].str, mcx.match[1].len);
	path2[mcx.match[1].len] = 0;

	if (strcmp(ri->local_uri, VULN_ENDPOINT) != 0) {
		mg_send_http_error(conn, 404, "Invalid path: %s\n", ri->local_uri);
		return 404;
	}

	// NOTE: BUG entry point
	if (strcmp(ri->request_method, "GET") == 0) {

		if (!ri->query_string) {
			mg_send_http_error(conn, 400, "No query string");
			return 400;
		} else if (strlen(ri->query_string) < 2) {
			mg_send_http_error(conn, 400, "Query string too short");
			return 400;
		}
		//fprintf(stderr, "Query string: %s\n", ri->query_string);
		//   Vulnerability simulation for the specific query 'q=fuzz'
		if (strncmp(ri->query_string, "q=fuzz", 6) == 0) {
			char buffer[64]; // This is a small local buffer

			// Vulnerability: We are copying the entire query_string into the
			// local buffer without checking its length
			strcpy(buffer, ri->query_string);

			mg_send_http_ok(conn, "text/plain", strlen(buffer));
			mg_write(conn, buffer, strlen(buffer));
			return 200;
		}
		mg_send_http_error(conn,
		                   400,
		                   "Invalid query string: %s\n",
		                   ri->query_string);
		return 400;
	}
	mg_send_http_error(conn, 405, "Only GET method supported");
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

	//std::string method =
	//    fuzzed_data.PickValueInArray({"GET", "POST", "PUT", "DELETE"});
	// NOTE: Instead of only polling the `VULN_ENDPOINT` endpoint we could
	// also build these endpoints by random or pick from a list of known good
	// ones!

	FuzzedDataProvider fuzzed_data(data, size);
	char* method = "GET";
	char* path = "/fuzz";
	char* parameter_name = "q";
	std::string input = fuzzed_data.ConsumeRemainingBytesAsString();
	char * parameter_value = &input[0];

	mg_printf(client,
	          "%s %s?%s=%s HTTP/1.1\r\n",
	          method,
	          path,
			  parameter_name,
	          parameter_value);
	mg_printf(client, "Host: %s\r\n", HOST);
	mg_printf(client, "Connection: close\r\n\r\n");

	mg_get_response(client, errbuf, sizeof(errbuf), -1);
	mg_close_connection(client);

	return;
}
