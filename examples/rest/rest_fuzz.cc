// Includes section
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

#include <chrono>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <thread>
#include <time.h>

#include "cJSON.h"
#include "civetweb.h"
// #include <assert.h>
// #include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>

// Constants
#define PORT "8089"
#define HOST_INFO "http://localhost:8089"
#define EXAMPLE_URI "/res/*/*"
#define EXAMPLE_FUZZ "/fuzz"
#define EXIT_URI "/exit"
#define HOST "localhost"

// Global variables
int exitNow = 0;
static unsigned request = 0; // Demo data: request counter

// Forward declarations
static int SendJSON(struct mg_connection *conn, cJSON *json_obj);
static int
ExampleGET(struct mg_connection *conn, const char *p1, const char *p2);
static int
ExampleDELETE(struct mg_connection *conn, const char *p1, const char *p2);
static int
ExamplePUT(struct mg_connection *conn, const char *p1, const char *p2);
static int FuzzHandler(struct mg_connection *conn, void *cbdata);
static int ExampleHandler(struct mg_connection *conn, void *cbdata);
static int ExitHandler(struct mg_connection *conn, void *cbdata);
static int log_message(const struct mg_connection *conn, const char *message);


static int
SendJSON(struct mg_connection *conn, cJSON *json_obj)
{
	char *json_str = cJSON_PrintUnformatted(json_obj);
	size_t json_str_len = strlen(json_str);

	/* Send HTTP message header (+1 for \n) */
	mg_send_http_ok(conn, "application/json; charset=utf-8", json_str_len + 1);

	/* Send HTTP message content */
	mg_write(conn, json_str, json_str_len);

	/* Add a newline. This is not required, but the result is more
	 * human-readable in a debugger. */
	mg_write(conn, "\n", 1);

	/* Free string allocated by cJSON_Print* */
	cJSON_free(json_str);

	return (int)json_str_len;
}


static int
ExampleGET(struct mg_connection *conn, const char *p1, const char *p2)
{
	cJSON *obj = cJSON_CreateObject();

	if (!obj) {
		/* insufficient memory? */
		mg_send_http_error(conn, 500, "Server error");
		return 500;
	}

	printf("GET %s/%s\n", p1, p2);
	cJSON_AddStringToObject(obj, "version", CIVETWEB_VERSION);
	cJSON_AddStringToObject(obj, "path1", p1);
	cJSON_AddStringToObject(obj, "path2", p2);
	cJSON_AddNumberToObject(obj, "request", ++request);
	SendJSON(conn, obj);
	cJSON_Delete(obj);

	return 200;
}


static int
ExampleDELETE(struct mg_connection *conn, const char *p1, const char *p2)
{
	printf("DELETE %s/%s\n", p1, p2);
	mg_send_http_error(conn,
	                   204,
	                   "%s",
	                   ""); /* Return "deleted" = "204 No Content" */

	return 204;
}


static int
ExamplePUT(struct mg_connection *conn, const char *p1, const char *p2)
{
	char buffer[1024];
	int dlen = mg_read(conn, buffer, sizeof(buffer) - 1);
	cJSON *obj, *elem;
	unsigned newvalue;

	printf("PUT %s/%s\n", p1, p2);
	if ((dlen < 1) || ((unsigned long)dlen >= sizeof(buffer))) {
		mg_send_http_error(conn, 400, "%s", "No request body data");
		return 400;
	}
	buffer[dlen] = 0;

	obj = cJSON_Parse(buffer);
	if (obj == NULL) {
		mg_send_http_error(conn, 400, "%s", "Invalid request body data");
		return 400;
	}

	elem = cJSON_GetObjectItemCaseSensitive(obj, "request");

	if (!cJSON_IsNumber(elem)) {
		cJSON_Delete(obj);
		mg_send_http_error(conn,
		                   400,
		                   "%s",
		                   "No \"request\" number in body data");
		return 400;
	}

	newvalue = (unsigned)elem->valuedouble;

	if ((double)newvalue != elem->valuedouble) {
		cJSON_Delete(obj);
		mg_send_http_error(conn,
		                   400,
		                   "%s",
		                   "Invalid \"request\" number in body data");
		return 400;
	}

	request = newvalue;
	cJSON_Delete(obj);

	mg_send_http_error(conn, 201, "%s", ""); /* Return "201 Created" */

	return 201;
}

static int
FuzzHandler(struct mg_connection *conn, void *cbdata)
{
	char path1[1024], path2[1024];
	const struct mg_request_info *ri = mg_get_request_info(conn);
	struct mg_match_context mcx;
	mcx.case_sensitive = 0;
	mg_match(EXAMPLE_FUZZ, ri->local_uri, &mcx);
	memcpy(path1, mcx.match[0].str, mcx.match[0].len);
	path1[mcx.match[0].len] = 0;
	memcpy(path2, mcx.match[1].str, mcx.match[1].len);
	path2[mcx.match[1].len] = 0;

	if (strcmp(ri->local_uri, EXAMPLE_FUZZ) != 0) {
		mg_send_http_error(conn, 404, "Invalid path: %s\n", ri->local_uri);
		return 404;
	}

	if (0 == strcmp(ri->request_method, "GET")) {
		//  Vulnerability simulation for the specific query 'q=fuzz'
		if (ri->query_string && strncmp(ri->query_string, "q=fuzz", 6) == 0) {
			char buffer[64]; // This is a small local buffer

			// Vulnerability: We are copying the entire query_string into the
			// local buffer without checking its length
			strcpy(buffer, ri->query_string);

			mg_send_http_ok(conn, "text/plain", strlen(buffer));
			mg_write(conn, buffer, strlen(buffer));

			// return ExampleGET(conn, path1, path2);
			return 200;
		}
	} else if ((0 == strcmp(ri->request_method, "PUT"))
	           || (0 == strcmp(ri->request_method, "POST"))
	           || (0 == strcmp(ri->request_method, "PATCH"))) {
		/* In this example, do the same for PUT, POST and PATCH */
		return ExamplePUT(conn, path1, path2);
	}
	if (0 == strcmp(ri->request_method, "DELETE")) {

		return ExampleDELETE(conn, path1, path2);
	}

	/* this is not a GET request */
	mg_send_http_error(
	    conn, 405, "Only GET, PUT, POST, DELETE and PATCH method supported");
	return 405;
}


static int
ExampleHandler(struct mg_connection *conn, void *cbdata)
{
	char path1[1024], path2[1024];
	const struct mg_request_info *ri = mg_get_request_info(conn);
	const char *url = ri->local_uri;
	size_t url_len = strlen(url);

	/* Pattern matching */
	struct mg_match_context mcx;
	mcx.case_sensitive = 0;
	ptrdiff_t ret = mg_match(EXAMPLE_URI, url, &mcx);
	if (((unsigned long)ret != url_len) || (mcx.num_matches != 2)) {
		/* Note: Could have done this with a $ at the end of the match
		 * pattern as well. Then we would have to check for a return value
		 * of -1 only. Here we use this version as minimum modification
		 * of the existing code. */
		printf("Match ret: %i\n", (int)ret);
		mg_send_http_error(conn, 404, "Invalid path: %s\n", url);
		return 404;
	}
	memcpy(path1, mcx.match[0].str, mcx.match[0].len);
	path1[mcx.match[0].len] = 0;
	memcpy(path2, mcx.match[1].str, mcx.match[1].len);
	path2[mcx.match[1].len] = 0;


	(void)cbdata; /* currently unused */

	/* According to method */
	if (0 == strcmp(ri->request_method, "GET")) {
		return ExampleGET(conn, path1, path2);
	}
	if ((0 == strcmp(ri->request_method, "PUT"))
	    || (0 == strcmp(ri->request_method, "POST"))
	    || (0 == strcmp(ri->request_method, "PATCH"))) {
		/* In this example, do the same for PUT, POST and PATCH */
		return ExamplePUT(conn, path1, path2);
	}
	if (0 == strcmp(ri->request_method, "DELETE")) {
		return ExampleDELETE(conn, path1, path2);
	}

	/* this is not a GET request */
	mg_send_http_error(
	    conn, 405, "Only GET, PUT, POST, DELETE and PATCH method supported");
	return 405;
}


static int
ExitHandler(struct mg_connection *conn, void *cbdata)
{
	mg_printf(conn,
	          "HTTP/1.1 200 OK\r\nContent-Type: "
	          "text/plain\r\nConnection: close\r\n\r\n");
	mg_printf(conn, "Server will shut down.\n");
	mg_printf(conn, "Bye!\n");
	exitNow = 1;
	return 1;
}


static int
log_message(const struct mg_connection *conn, const char *message)
{
	puts(message);
	return 1;
}

struct mg_callbacks callbacks;
struct mg_context *ctx;

int
one_time_setup()
{
	const char *options[] = {"listening_ports",
	                         PORT,
	                         "request_timeout_ms",
	                         "10000",
	                         "error_log_file",
	                         "error.log",
	                         0};

	/* Init libcivetweb. */
	mg_init_library(0);

	/* Callback will print error messages to console */
	memset(&callbacks, 0, sizeof(callbacks));
	callbacks.log_message = log_message;

	/* Start CivetWeb web server */
	ctx = mg_start(&callbacks, 0, options);

	/* Check return value: */
	if (ctx == NULL) {
		fprintf(stderr, "Cannot start CivetWeb - mg_start failed.\n");
		return EXIT_FAILURE;
		// return;
	}

	/* Add handler EXAMPLE_URI, to explain the example */
	mg_set_request_handler(ctx, EXAMPLE_URI, ExampleHandler, 0);
	mg_set_request_handler(ctx, EXIT_URI, ExitHandler, 0);
	mg_set_request_handler(ctx, EXAMPLE_FUZZ, FuzzHandler, 0);

	/* Show some info */
	printf("Start example: %s%s\n", HOST_INFO, EXAMPLE_URI);
	printf("Fuzz example: %s%s\n", HOST_INFO, EXAMPLE_FUZZ);
	printf("Exit example:  %s%s\n", HOST_INFO, EXIT_URI);
	return 0;
	// return;
}

extern "C" int
LLVMFuzzerInitialize(int *argc, char ***argv)
// FUZZ_TEST_SETUP()
{
	return one_time_setup();
}

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
// FUZZ_TEST(const uint8_t *data, size_t size)
{

	int err = false;
	if (err) {
		one_time_setup();
	}

	FuzzedDataProvider fuzzed_data(data, size);

	char errbuf[256] = {0};
	struct mg_connection *cli =
	    mg_connect_client(HOST, atoi(PORT), 0, errbuf, sizeof(errbuf));

	if (cli == NULL) {
		fprintf(stderr, "Cannot connect client: %s\n", errbuf);
		err = true;
		return EXIT_FAILURE;
		// return;
	}

	std::string method =
	    fuzzed_data.PickValueInArray({"GET", "POST", "PUT", "DELETE"});
	mg_printf(cli,
	          "%s %s?q=%s HTTP/1.1\r\n",
	          "GET",
	          EXAMPLE_FUZZ,
	          fuzzed_data.ConsumeRemainingBytesAsString().c_str());
	mg_printf(cli, "Host: %s\r\n", HOST);
	mg_printf(cli, "Connection: close\r\n\r\n");

	mg_get_response(cli, errbuf, sizeof(errbuf), 10000);
	// std::this_thread::sleep_for(std::chrono::milliseconds(30));
	mg_close_connection(cli);
	return EXIT_SUCCESS;
}
