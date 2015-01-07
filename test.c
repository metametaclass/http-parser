/* Copyright Joyent, Inc. and other Node contributors. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#include "http_parser.h"
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h> /* rand */
#include <string.h>
#include <stdarg.h>

#ifdef _MSC_VER
#include <crtdbg.h>
#include <windows.h>
#endif

#if defined(__APPLE__)
# undef strlcat
# undef strlncpy
# undef strlcpy
#endif  /* defined(__APPLE__) */

#if defined(_MSC_VER)
#define INLINE __inline
#endif

#undef TRUE
#define TRUE 1
#undef FALSE
#define FALSE 0

#define MAX_HEADERS 13
#define MAX_ELEMENT_SIZE 2048

#define MIN(a,b) ((a) < (b) ? (a) : (b))

static http_parser *parser;

struct message {
  const char *name; // for debugging purposes
  const char *raw;
  enum http_parser_type type;
  enum http_method method;
  int status_code;
  char response_status[MAX_ELEMENT_SIZE];
  char request_path[MAX_ELEMENT_SIZE];
  char request_url[MAX_ELEMENT_SIZE];
  char fragment[MAX_ELEMENT_SIZE];
  char query_string[MAX_ELEMENT_SIZE];
  char body[MAX_ELEMENT_SIZE];
  size_t body_size;
  const char *host;
  const char *userinfo;
  uint16_t port;
  int num_headers;
  enum { NONE=0, FIELD, VALUE } last_header_element;
  char headers [MAX_HEADERS][2][MAX_ELEMENT_SIZE];
  int should_keep_alive;

  const char *upgrade; // upgraded body

  unsigned short http_major;
  unsigned short http_minor;

  int message_begin_cb_called;
  int headers_complete_cb_called;
  int message_complete_cb_called;
  int message_complete_on_eof;
  int body_is_final;
};

static int currently_parsing_eof;

static struct message messages[5];
static int num_messages;
static http_parser_settings *current_pause_parser;

#ifdef TEST_CASES
/* * R E Q U E S T S * */
const struct message requests[] =
{ 
    {0}
};

#define CURL_GET 0
#define FIREFOX_GET 1
#define DUMBFUCK 2
#define FRAGMENT_IN_URI 3
#define GET_NO_HEADERS_NO_BODY 4
#define GET_ONE_HEADER_NO_BODY 5
#define GET_FUNKY_CONTENT_LENGTH 6
#define POST_IDENTITY_BODY_WORLD 7
#define POST_CHUNKED_ALL_YOUR_BASE 8
#define TWO_CHUNKS_MULT_ZERO_END 9
#define CHUNKED_W_TRAILING_HEADERS 10
#define CHUNKED_W_BULLSHIT_AFTER_LENGTH 11
#define WITH_QUOTES 12
#define APACHEBENCH_GET 13
#define QUERY_URL_WITH_QUESTION_MARK_GET 14
#define PREFIX_NEWLINE_GET 15
#define UPGRADE_REQUEST 16
#define CONNECT_REQUEST 17
#define REPORT_REQ 18
#define NO_HTTP_VERSION 19
#define MSEARCH_REQ 20
#define LINE_FOLDING_IN_HEADER 21
#define QUERY_TERMINATED_HOST 22
#define QUERY_TERMINATED_HOSTPORT 23
#define SPACE_TERMINATED_HOSTPORT 24
#define PATCH_REQ 25
#define CONNECT_CAPS_REQUEST 26
#define UTF8_PATH_REQ 27
#define HOSTNAME_UNDERSCORE 28
#define EAT_TRAILING_CRLF_NO_CONNECTION_CLOSE 29
#define EAT_TRAILING_CRLF_WITH_CONNECTION_CLOSE 30
#define PURGE_REQ 31
#define SEARCH_REQ 32
#define PROXY_WITH_BASIC_AUTH 33
#define LINE_FOLDING_IN_HEADER_WITH_LF 34
#define CONNECTION_MULTI 35


/* * R E S P O N S E S * */
const struct message responses[] =
{
    {0}
};

#define GOOGLE_301 0
#define NO_CONTENT_LENGTH_RESPONSE 1
#define NO_HEADERS_NO_BODY_404 2
#define NO_REASON_PHRASE 3
#define TRAILING_SPACE_ON_CHUNKED_BODY 4
#define NO_CARRIAGE_RET 5
#define PROXY_CONNECTION 6
#define UNDERSTORE_HEADER_KEY 7
#define BONJOUR_MADAME_FR 8
#define RES_FIELD_UNDERSCORE 9
#define NON_ASCII_IN_STATUS_LINE 10
#define HTTP_VERSION_0_9 11
#define NO_CONTENT_LENGTH_NO_TRANSFER_ENCODING_RESPONSE 12
#define NO_BODY_HTTP10_KA_200 13
#define NO_BODY_HTTP10_KA_204 14
#define NO_BODY_HTTP11_KA_200 15
#define NO_BODY_HTTP11_KA_204 16
#define NO_BODY_HTTP11_NOKA_204 17
#define NO_BODY_HTTP11_KA_CHUNKED_200 18
#define SPACE_IN_FIELD_RES 19
#define AMAZON_COM 20
#define EMPTY_REASON_PHRASE_AFTER_SPACE 20

#endif //ifdef TEST_CASES

/* strnlen() is a POSIX.2008 addition. Can't rely on it being available so
 * define it ourselves.
 */
size_t
strnlen(const char *s, size_t maxlen)
{
  const char *p;

  p = (char*) memchr(s, '\0', maxlen);
  if (p == NULL)
    return maxlen;

  return p - s;
}

size_t
strlncat(char *dst, size_t len, const char *src, size_t n)
{
  size_t slen;
  size_t dlen;
  size_t rlen;
  size_t ncpy;

  slen = strnlen(src, n);
  dlen = strnlen(dst, len);

  if (dlen < len) {
    rlen = len - dlen;
    ncpy = slen < rlen ? slen : (rlen - 1);
    memcpy(dst + dlen, src, ncpy);
    dst[dlen + ncpy] = '\0';
  }

  assert(len > slen + dlen);
  return slen + dlen;
}

size_t
strlcat(char *dst, const char *src, size_t len)
{
  return strlncat(dst, len, src, (size_t) -1);
}

size_t
strlncpy(char *dst, size_t len, const char *src, size_t n)
{
  size_t slen;
  size_t ncpy;

  slen = strnlen(src, n);

  if (len > 0) {
    ncpy = slen < len ? slen : (len - 1);
    memcpy(dst, src, ncpy);
    dst[ncpy] = '\0';
  }

  assert(len > slen);
  return slen;
}

size_t
strlcpy(char *dst, const char *src, size_t len)
{
  return strlncpy(dst, len, src, (size_t) -1);
}

int
request_url_cb (http_parser *p, const char *buf, size_t len)
{
  assert(p == parser);
  strlncat(messages[num_messages].request_url,
           sizeof(messages[num_messages].request_url),
           buf,
           len);
  return 0;
}

int
header_field_cb (http_parser *p, const char *buf, size_t len)
{
  struct message *m;
  assert(p == parser);
  m = &messages[num_messages];

  if (m->last_header_element != FIELD)
    m->num_headers++;

  strlncat(m->headers[m->num_headers-1][0],
           sizeof(m->headers[m->num_headers-1][0]),
           buf,
           len);

  m->last_header_element = FIELD;

  return 0;
}

int
header_value_cb (http_parser *p, const char *buf, size_t len)
{
  struct message *m;
  assert(p == parser);
  m = &messages[num_messages];

  strlncat(m->headers[m->num_headers-1][1],
           sizeof(m->headers[m->num_headers-1][1]),
           buf,
           len);

  m->last_header_element = VALUE;

  return 0;
}

void
check_body_is_final (const http_parser *p)
{
  if (messages[num_messages].body_is_final) {
    fprintf(stderr, "\n\n *** Error http_body_is_final() should return 1 "
                    "on last on_body callback call "
                    "but it doesn't! ***\n\n");
    assert(0);
    abort();
  }
  messages[num_messages].body_is_final = http_body_is_final(p);
}

int
body_cb (http_parser *p, const char *buf, size_t len)
{
  assert(p == parser);
  strlncat(messages[num_messages].body,
           sizeof(messages[num_messages].body),
           buf,
           len);
  messages[num_messages].body_size += len;
  check_body_is_final(p);
 // printf("body_cb: '%s'\n", requests[num_messages].body);
  return 0;
}

int
count_body_cb (http_parser *p, const char *buf, size_t len)
{
  assert(p == parser);
  assert(buf);
  messages[num_messages].body_size += len;
  check_body_is_final(p);
  return 0;
}

int
message_begin_cb (http_parser *p)
{
  assert(p == parser);
  messages[num_messages].message_begin_cb_called = TRUE;
  return 0;
}

int
headers_complete_cb (http_parser *p)
{
  assert(p == parser);
  messages[num_messages].method = parser->method;
  messages[num_messages].status_code = parser->status_code;
  messages[num_messages].http_major = parser->http_major;
  messages[num_messages].http_minor = parser->http_minor;
  messages[num_messages].headers_complete_cb_called = TRUE;
  messages[num_messages].should_keep_alive = http_should_keep_alive(parser);
  return 0;
}

int
message_complete_cb (http_parser *p)
{
  assert(p == parser);
  if (messages[num_messages].should_keep_alive != http_should_keep_alive(parser))
  {
    fprintf(stderr, "\n\n *** Error http_should_keep_alive() should have same "
                    "value in both on_message_complete and on_headers_complete "
                    "but it doesn't! ***\n\n");
    assert(0);
    abort();
  }

  if (messages[num_messages].body_size &&
      http_body_is_final(p) &&
      !messages[num_messages].body_is_final)
  {
    fprintf(stderr, "\n\n *** Error http_body_is_final() should return 1 "
                    "on last on_body callback call "
                    "but it doesn't! ***\n\n");
    assert(0);
    abort();
  }

  messages[num_messages].message_complete_cb_called = TRUE;

  messages[num_messages].message_complete_on_eof = currently_parsing_eof;

  num_messages++;
  return 0;
}

int
response_status_cb (http_parser *p, const char *buf, size_t len)
{
  assert(p == parser);
  strlncat(messages[num_messages].response_status,
           sizeof(messages[num_messages].response_status),
           buf,
           len);
  return 0;
}

/* These dontcall_* callbacks exist so that we can verify that when we're
 * paused, no additional callbacks are invoked */
int
dontcall_message_begin_cb (http_parser *p)
{
  if (p) { } // gcc
  fprintf(stderr, "\n\n*** on_message_begin() called on paused parser ***\n\n");
  abort();
  return 0;
}

int
dontcall_header_field_cb (http_parser *p, const char *buf, size_t len)
{
  if (p || buf || len) { } // gcc
  fprintf(stderr, "\n\n*** on_header_field() called on paused parser ***\n\n");
  abort();
  return 0;
}

int
dontcall_header_value_cb (http_parser *p, const char *buf, size_t len)
{
  if (p || buf || len) { } // gcc
  fprintf(stderr, "\n\n*** on_header_value() called on paused parser ***\n\n");
  abort();
  return 0;
}

int
dontcall_request_url_cb (http_parser *p, const char *buf, size_t len)
{
  if (p || buf || len) { } // gcc
  fprintf(stderr, "\n\n*** on_request_url() called on paused parser ***\n\n");
  abort();
  return 0;
}

int
dontcall_body_cb (http_parser *p, const char *buf, size_t len)
{
  if (p || buf || len) { } // gcc
  fprintf(stderr, "\n\n*** on_body_cb() called on paused parser ***\n\n");
  abort();
  return 0;
}

int
dontcall_headers_complete_cb (http_parser *p)
{
  if (p) { } // gcc
  fprintf(stderr, "\n\n*** on_headers_complete() called on paused "
                  "parser ***\n\n");
  abort();
  return 0;
}

int
dontcall_message_complete_cb (http_parser *p)
{
  if (p) { } // gcc
  fprintf(stderr, "\n\n*** on_message_complete() called on paused "
                  "parser ***\n\n");
  abort();
  return 0;
}

int
dontcall_response_status_cb (http_parser *p, const char *buf, size_t len)
{
  if (p || buf || len) { } // gcc
  fprintf(stderr, "\n\n*** on_status() called on paused parser ***\n\n");
  abort();
  return 0;
}


static http_parser_settings settings_dontcall =
  {dontcall_message_begin_cb,   //on_message_begin;
   dontcall_request_url_cb,     //on_url
   dontcall_response_status_cb, //on_status
   dontcall_header_field_cb,     //on_header_field
   dontcall_header_value_cb,     //on_header_value
   dontcall_headers_complete_cb, //on_headers_complete
   dontcall_body_cb,             //on_body
   dontcall_message_complete_cb, //on_message_complete
  };

/* These pause_* callbacks always pause the parser and just invoke the regular
 * callback that tracks content. Before returning, we overwrite the parser
 * settings to point to the _dontcall variety so that we can verify that
 * the pause actually did, you know, pause. */
int
pause_message_begin_cb (http_parser *p)
{
  http_parser_pause(p, 1);
  *current_pause_parser = settings_dontcall;
  return message_begin_cb(p);
}

int
pause_header_field_cb (http_parser *p, const char *buf, size_t len)
{
  http_parser_pause(p, 1);
  *current_pause_parser = settings_dontcall;
  return header_field_cb(p, buf, len);
}

int
pause_header_value_cb (http_parser *p, const char *buf, size_t len)
{
  http_parser_pause(p, 1);
  *current_pause_parser = settings_dontcall;
  return header_value_cb(p, buf, len);
}

int
pause_request_url_cb (http_parser *p, const char *buf, size_t len)
{
  http_parser_pause(p, 1);
  *current_pause_parser = settings_dontcall;
  return request_url_cb(p, buf, len);
}

int
pause_body_cb (http_parser *p, const char *buf, size_t len)
{
  http_parser_pause(p, 1);
  *current_pause_parser = settings_dontcall;
  return body_cb(p, buf, len);
}

int
pause_headers_complete_cb (http_parser *p)
{
  http_parser_pause(p, 1);
  *current_pause_parser = settings_dontcall;
  return headers_complete_cb(p);
}

int
pause_message_complete_cb (http_parser *p)
{
  http_parser_pause(p, 1);
  *current_pause_parser = settings_dontcall;
  return message_complete_cb(p);
}

int
pause_response_status_cb (http_parser *p, const char *buf, size_t len)
{
  http_parser_pause(p, 1);
  *current_pause_parser = settings_dontcall;
  return response_status_cb(p, buf, len);
}

static http_parser_settings settings_pause =
  {pause_message_begin_cb,
   pause_request_url_cb,
   pause_response_status_cb,
   pause_header_field_cb,
   pause_header_value_cb,
   pause_headers_complete_cb,
   pause_body_cb,
   pause_message_complete_cb
  };

static http_parser_settings settings =
  {message_begin_cb
  ,request_url_cb
  ,response_status_cb 
  ,header_field_cb
  ,header_value_cb
  ,headers_complete_cb
  ,body_cb  
  ,message_complete_cb
  };

static http_parser_settings settings_count_body =
  {message_begin_cb
  ,request_url_cb
  ,response_status_cb
  ,header_field_cb
  ,header_value_cb
  ,headers_complete_cb
  ,count_body_cb  
  ,message_complete_cb
  };

static http_parser_settings settings_null =
  {0
  ,0
  ,0
  ,0
  ,0
  ,0
  ,0
  ,0
  };

void
parser_init (enum http_parser_type type)
{
  num_messages = 0;

  assert(parser == NULL);

  parser = (http_parser*) malloc(sizeof(http_parser));

  http_parser_init(parser, type);

  memset(&messages, 0, sizeof messages);

}

void
parser_free ()
{
  assert(parser);
  free(parser);
  parser = NULL;
}

size_t parse (const char *buf, size_t len)
{
  size_t nparsed;
  currently_parsing_eof = (len == 0);
  nparsed = http_parser_execute(parser, &settings, buf, len);
  return nparsed;
}

size_t parse_count_body (const char *buf, size_t len)
{
  size_t nparsed;
  currently_parsing_eof = (len == 0);
  nparsed = http_parser_execute(parser, &settings_count_body, buf, len);
  return nparsed;
}

size_t parse_pause (const char *buf, size_t len)
{
  size_t nparsed;
  http_parser_settings s = settings_pause;

  currently_parsing_eof = (len == 0);
  current_pause_parser = &s;
  nparsed = http_parser_execute(parser, current_pause_parser, buf, len);
  return nparsed;
}

static INLINE int
check_str_eq (const struct message *m,
              const char *prop,
              const char *expected,
              const char *found) {
  if ((expected == NULL) != (found == NULL)) {
    printf("\n*** Error: %s in '%s' ***\n\n", prop, m->name);
    printf("expected %s\n", (expected == NULL) ? "NULL" : expected);
    printf("   found %s\n", (found == NULL) ? "NULL" : found);
    return 0;
  }
  if (expected != NULL && 0 != strcmp(expected, found)) {
    printf("\n*** Error: %s in '%s' ***\n\n", prop, m->name);
    printf("expected '%s'\n", expected);
    printf("   found '%s'\n", found);
    return 0;
  }
  return 1;
}

static INLINE int
check_num_eq (const struct message *m,
              const char *prop,
              int expected,
              int found) {
  if (expected != found) {
    printf("\n*** Error: %s in '%s' ***\n\n", prop, m->name);
    printf("expected %d\n", expected);
    printf("   found %d\n", found);
    return 0;
  }
  return 1;
}

#define MESSAGE_CHECK_STR_EQ(expected, found, prop) \
  if (!check_str_eq(expected, #prop, expected->prop, found->prop)) return 0

#define MESSAGE_CHECK_NUM_EQ(expected, found, prop) \
  if (!check_num_eq(expected, #prop, expected->prop, found->prop)) return 0

#define MESSAGE_CHECK_URL_EQ(u, expected, found, prop, fn)           \
do {                                                                 \
  char ubuf[256];                                                    \
                                                                     \
  if ((u)->field_set & (1 << (fn))) {                                \
    memcpy(ubuf, (found)->request_url + (u)->field_data[(fn)].off,   \
      (u)->field_data[(fn)].len);                                    \
    ubuf[(u)->field_data[(fn)].len] = '\0';                          \
  } else {                                                           \
    ubuf[0] = '\0';                                                  \
  }                                                                  \
                                                                     \
  check_str_eq(expected, #prop, expected->prop, ubuf);               \
} while(0)

int
message_eq (int index, const struct message *expected)
{
  int i;
  int r;
  struct message *m = &messages[index];

  MESSAGE_CHECK_NUM_EQ(expected, m, http_major);
  MESSAGE_CHECK_NUM_EQ(expected, m, http_minor);

  if (expected->type == HTTP_REQUEST) {
    MESSAGE_CHECK_NUM_EQ(expected, m, method);
  } else {
    MESSAGE_CHECK_NUM_EQ(expected, m, status_code);
    MESSAGE_CHECK_STR_EQ(expected, m, response_status);
  }

  MESSAGE_CHECK_NUM_EQ(expected, m, should_keep_alive);
  MESSAGE_CHECK_NUM_EQ(expected, m, message_complete_on_eof);

  assert(m->message_begin_cb_called);
  assert(m->headers_complete_cb_called);
  assert(m->message_complete_cb_called);


  MESSAGE_CHECK_STR_EQ(expected, m, request_url);

  /* Check URL components; we can't do this w/ CONNECT since it doesn't
   * send us a well-formed URL.
   */
  if (*m->request_url && m->method != HTTP_CONNECT) {
    struct http_parser_url u;

    if (http_parser_parse_url(m->request_url, strlen(m->request_url), 0, &u)) {
      fprintf(stderr, "\n\n*** failed to parse URL %s ***\n\n",
        m->request_url);
      abort();
    }

    if (expected->host) {
      MESSAGE_CHECK_URL_EQ(&u, expected, m, host, UF_HOST);
    }

    if (expected->userinfo) {
      MESSAGE_CHECK_URL_EQ(&u, expected, m, userinfo, UF_USERINFO);
    }

    m->port = (u.field_set & (1 << UF_PORT)) ?
      u.port : 0;

    MESSAGE_CHECK_URL_EQ(&u, expected, m, query_string, UF_QUERY);
    MESSAGE_CHECK_URL_EQ(&u, expected, m, fragment, UF_FRAGMENT);
    MESSAGE_CHECK_URL_EQ(&u, expected, m, request_path, UF_PATH);
    MESSAGE_CHECK_NUM_EQ(expected, m, port);
  }

  if (expected->body_size) {
    MESSAGE_CHECK_NUM_EQ(expected, m, body_size);
  } else {
    MESSAGE_CHECK_STR_EQ(expected, m, body);
  }

  MESSAGE_CHECK_NUM_EQ(expected, m, num_headers);

  
  for (i = 0; i < m->num_headers; i++) {
    r = check_str_eq(expected, "header field", expected->headers[i][0], m->headers[i][0]);
    if (!r) return 0;
    r = check_str_eq(expected, "header value", expected->headers[i][1], m->headers[i][1]);
    if (!r) return 0;
  }

  MESSAGE_CHECK_STR_EQ(expected, m, upgrade);

  return 1;
}

/* Given a sequence of varargs messages, return the number of them that the
 * parser should successfully parse, taking into account that upgraded
 * messages prevent all subsequent messages from being parsed.
 */
size_t
count_parsed_messages(const size_t nmsgs, ...) {
  size_t i;
  va_list ap;

  va_start(ap, nmsgs);

  for (i = 0; i < nmsgs; i++) {
    struct message *m = va_arg(ap, struct message *);

    if (m->upgrade) {
      va_end(ap);
      return i + 1;
    }
  }

  va_end(ap);
  return nmsgs;
}

/* Given a sequence of bytes and the number of these that we were able to
 * parse, verify that upgrade bodies are correct.
 */
void
upgrade_message_fix(char *body, const size_t nread, const size_t nmsgs, ...) {
  va_list ap;
  size_t i;
  size_t off = 0;
 
  va_start(ap, nmsgs);

  for (i = 0; i < nmsgs; i++) {
    struct message *m = va_arg(ap, struct message *);

    off += strlen(m->raw);

    if (m->upgrade) {
      off -= strlen(m->upgrade);

      /* Check the portion of the response after its specified upgrade */
      if (!check_str_eq(m, "upgrade", body + off, body + nread)) {
        abort();
      }

      /* Fix up the response so that message_eq() will verify the beginning
       * of the upgrade */
      *(body + nread + strlen(m->upgrade)) = '\0';
      messages[num_messages -1 ].upgrade = body + nread;

      va_end(ap);
      return;
    }
  }

  va_end(ap);
  printf("\n\n*** Error: expected a message with upgrade ***\n");

  abort();
}

static void
print_error (const char *raw, size_t error_location)
{
  int this_line = 0, char_len = 0;
  size_t i, j, len, error_location_line;

  fprintf(stderr, "\n*** %s ***\n\n",
          http_errno_description(HTTP_PARSER_ERRNO(parser)));
    
  len = strlen(raw), error_location_line = 0;
  for (i = 0; i < len; i++) {
    if (i == error_location) this_line = 1;
    switch (raw[i]) {
      case '\r':
        char_len = 2;
        fprintf(stderr, "\\r");
        break;

      case '\n':
        fprintf(stderr, "\\n\n");

        if (this_line) goto print;

        error_location_line = 0;
        continue;

      default:
        char_len = 1;
        fputc(raw[i], stderr);
        break;
    }
    if (!this_line) error_location_line += char_len;
  }

  fprintf(stderr, "[eof]\n");

 print:
  for (j = 0; j < error_location_line; j++) {
    fputc(' ', stderr);
  }
  fprintf(stderr, "^\n\nerror location: %u\n", (unsigned int)error_location);
}

void
test_preserve_data (void)
{
  char my_data[] = "application-specific data";
  http_parser parser;
  parser.data = my_data;
  http_parser_init(&parser, HTTP_REQUEST);
  if (parser.data != my_data) {
    printf("\n*** parser.data not preserved accross http_parser_init ***\n\n");
    abort();
  }
}

struct url_test {
  const char *name;
  const char *url;
  int is_connect;
  struct http_parser_url u;
  int rv;
};

#ifdef TEST_URLS
const struct url_test url_tests[] =
{ 
    {0}
};
#endif

void
dump_url (const char *url, const struct http_parser_url *u)
{
  unsigned int i;

  printf("\tfield_set: 0x%x, port: %u\n", u->field_set, u->port);
  for (i = 0; i < UF_MAX; i++) {
    if ((u->field_set & (1 << i)) == 0) {
      printf("\tfield_data[%u]: unset\n", i);
      continue;
    }

    printf("\tfield_data[%u]: off: %u len: %u part: \"%.*s\n\"",
           i,
           u->field_data[i].off,
           u->field_data[i].len,
           u->field_data[i].len,
           url + u->field_data[i].off);
  }
}

void
test_parse_url (void)
{
#ifdef TEST_URLS
  struct http_parser_url u;
  const struct url_test *test;
  unsigned int i;
  int rv;

  for (i = 0; i < (sizeof(url_tests) / sizeof(url_tests[0])); i++) {
    test = &url_tests[i];
    memset(&u, 0, sizeof(u));

    rv = http_parser_parse_url(test->url,
                               strlen(test->url),
                               test->is_connect,
                               &u);

    if (test->rv == 0) {
      if (rv != 0) {
        printf("\n*** http_parser_parse_url(\"%s\") \"%s\" test failed, "
               "unexpected rv %d ***\n\n", test->url, test->name, rv);
        abort();
      }

      if (memcmp(&u, &test->u, sizeof(u)) != 0) {
        printf("\n*** http_parser_parse_url(\"%s\") \"%s\" failed ***\n",
               test->url, test->name);

        printf("target http_parser_url:\n");
        dump_url(test->url, &test->u);
        printf("result http_parser_url:\n");
        dump_url(test->url, &u);

        abort();
      }
    } else {
      /* test->rv != 0 */
      if (rv == 0) {
        printf("\n*** http_parser_parse_url(\"%s\") \"%s\" test failed, "
               "unexpected rv %d ***\n\n", test->url, test->name, rv);
        abort();
      }
    }
  }
#endif
}

void
test_method_str (void)
{
  assert(0 == strcmp("GET", http_method_str(HTTP_GET)));
  assert(0 == strcmp("<unknown>", http_method_str((enum http_method)1337)));
}

void
test_message (const struct message *message)
{
  const char *msg1;
  const char *msg2;
  size_t raw_len = strlen(message->raw);
  size_t msg1len;
  size_t msg2len;
  size_t read;

  for (msg1len = 0; msg1len < raw_len; msg1len++) {
    parser_init(message->type);
    
    msg1 = message->raw;
    msg2 = msg1 + msg1len;
    msg2len = raw_len - msg1len;

    if (msg1len) {
      read = parse(msg1, msg1len);

      if (message->upgrade && parser->upgrade) {
        messages[num_messages - 1].upgrade = msg1 + read;
        goto test;
      }

      if (read != msg1len) {
        print_error(msg1, read);
        abort();
      }
    }


    read = parse(msg2, msg2len);

    if (message->upgrade && parser->upgrade) {
      messages[num_messages - 1].upgrade = msg2 + read;
      goto test;
    }

    if (read != msg2len) {
      print_error(msg2, read);
      abort();
    }

    read = parse(NULL, 0);

    if (read != 0) {
      print_error(message->raw, read);
      abort();
    }

  test:

    if (num_messages != 1) {
      printf("\n*** num_messages != 1 after testing '%s' ***\n\n", message->name);
      abort();
    }

    if(!message_eq(0, message)) abort();

    parser_free();
  }
}

void
test_message_count_body (const struct message *message)
{
  size_t read;
  size_t l;
  size_t i, toread;
  size_t chunk = 4024;

  parser_init(message->type);

  l = strlen(message->raw);    

  for (i = 0; i < l; i+= chunk) {
    toread = MIN(l-i, chunk);
    read = parse_count_body(message->raw + i, toread);
    if (read != toread) {
      print_error(message->raw, read);
      abort();
    }
  }


  read = parse_count_body(NULL, 0);
  if (read != 0) {
    print_error(message->raw, read);
    abort();
  }

  if (num_messages != 1) {
    printf("\n*** num_messages != 1 after testing '%s' ***\n\n", message->name);
    abort();
  }

  if(!message_eq(0, message)) abort();

  parser_free();
}

void
test_simple (const char *buf, enum http_errno err_expected)
{
  enum http_errno err;
  parser_init(HTTP_REQUEST);  

  parse(buf, strlen(buf));
  err = HTTP_PARSER_ERRNO(parser);
  parse(NULL, 0);

  parser_free();

  /* In strict mode, allow us to pass with an unexpected HPE_STRICT as
   * long as the caller isn't expecting success.
   */
#if HTTP_PARSER_STRICT
  if (err_expected != err && err_expected != HPE_OK && err != HPE_STRICT) {
#else
  if (err_expected != err) {
#endif
    fprintf(stderr, "\n*** test_simple expected %s, but saw %s ***\n\n%s\n",
        http_errno_name(err_expected), http_errno_name(err), buf);
    abort();
  }
}

void
test_header_overflow_error (int req)
{
  http_parser parser;
  size_t parsed;
  const char *buf;
  size_t buflen;
  int i;

  http_parser_init(&parser, req ? HTTP_REQUEST : HTTP_RESPONSE);  
  buf = req ? "GET / HTTP/1.1\r\n" : "HTTP/1.0 200 OK\r\n";
  parsed = http_parser_execute(&parser, &settings_null, buf, strlen(buf));
  assert(parsed == strlen(buf));

  buf = "header-key: header-value\r\n";
  buflen = strlen(buf);

  
  for (i = 0; i < 10000; i++) {
    parsed = http_parser_execute(&parser, &settings_null, buf, buflen);
    if (parsed != buflen) {
      //fprintf(stderr, "error found on iter %d\n", i);
      assert(HTTP_PARSER_ERRNO(&parser) == HPE_HEADER_OVERFLOW);
      return;
    }
  }

  fprintf(stderr, "\n*** Error expected but none in header overflow test ***\n");
  abort();
}

static void
test_content_length_overflow (const char *buf, size_t buflen, int expect_ok)
{
  http_parser parser;
  http_parser_init(&parser, HTTP_RESPONSE);
  http_parser_execute(&parser, &settings_null, buf, buflen);

  if (expect_ok)
    assert(HTTP_PARSER_ERRNO(&parser) == HPE_OK);
  else
    assert(HTTP_PARSER_ERRNO(&parser) == HPE_INVALID_CONTENT_LENGTH);
}

void
test_header_content_length_overflow_error (void)
{
#define X(size)                                                               \
  "HTTP/1.1 200 OK\r\n"                                                       \
  "Content-Length: " #size "\r\n"                                             \
  "\r\n"
  const char a[] = X(1844674407370955160);  /* 2^64 / 10 - 1 */
  const char b[] = X(18446744073709551615); /* 2^64-1 */
  const char c[] = X(18446744073709551616); /* 2^64   */
#undef X
  test_content_length_overflow(a, sizeof(a) - 1, 1); /* expect ok      */
  test_content_length_overflow(b, sizeof(b) - 1, 0); /* expect failure */
  test_content_length_overflow(c, sizeof(c) - 1, 0); /* expect failure */
}

void
test_chunk_content_length_overflow_error (void)
{
#define X(size)                                                               \
    "HTTP/1.1 200 OK\r\n"                                                     \
    "Transfer-Encoding: chunked\r\n"                                          \
    "\r\n"                                                                    \
    #size "\r\n"                                                              \
    "..."
  const char a[] = X(FFFFFFFFFFFFFFE);   /* 2^64 / 16 - 1 */
  const char b[] = X(FFFFFFFFFFFFFFFF);  /* 2^64-1 */
  const char c[] = X(10000000000000000); /* 2^64   */
#undef X
  test_content_length_overflow(a, sizeof(a) - 1, 1); /* expect ok      */
  test_content_length_overflow(b, sizeof(b) - 1, 0); /* expect failure */
  test_content_length_overflow(c, sizeof(c) - 1, 0); /* expect failure */
}

void
test_no_overflow_long_body (int req, size_t length)
{
  http_parser parser;
  size_t parsed;
  size_t i;
  char buf1[3000];
  size_t buf1len;

  http_parser_init(&parser, req ? HTTP_REQUEST : HTTP_RESPONSE);
  
  buf1len = sprintf(buf1, "%s\r\nConnection: Keep-Alive\r\nContent-Length: %lu\r\n\r\n",
      req ? "POST / HTTP/1.0" : "HTTP/1.0 200 OK", (unsigned long)length);
  parsed = http_parser_execute(&parser, &settings_null, buf1, buf1len);
  if (parsed != buf1len)
    goto err;

  for (i = 0; i < length; i++) {
    char foo = 'a';
    parsed = http_parser_execute(&parser, &settings_null, &foo, 1);
    if (parsed != 1)
      goto err;
  }

  parsed = http_parser_execute(&parser, &settings_null, buf1, buf1len);
  if (parsed != buf1len) goto err;
  return;

 err:
  fprintf(stderr,
          "\n*** error in test_no_overflow_long_body %s of length %lu ***\n",
          req ? "REQUEST" : "RESPONSE",
          (unsigned long)length);
  abort();
}

void
test_multiple3 (const struct message *r1, const struct message *r2, const struct message *r3)
{
  int message_count = count_parsed_messages(3, r1, r2, r3);
  size_t read;
  char *total = (char*)malloc(strlen(r1->raw)
                            + strlen(r2->raw)
                            + strlen(r3->raw)
                            + 1);

  total[0] = '\0';

  strcat(total, r1->raw);
  strcat(total, r2->raw);
  strcat(total, r3->raw);

  parser_init(r1->type);

  

  read = parse(total, strlen(total));

  if (parser->upgrade) {
    upgrade_message_fix(total, read, 3, r1, r2, r3);
    goto test;
  }

  if (read != strlen(total)) {
    print_error(total, read);
    abort();
  }

  read = parse(NULL, 0);

  if (read != 0) {
    print_error(total, read);
    abort();
  }

test:

  if (message_count != num_messages) {
    fprintf(stderr, "\n\n*** Parser didn't see 3 messages only %d *** \n", num_messages);
    abort();
  }

  if (!message_eq(0, r1)) abort();
  if (message_count > 1 && !message_eq(1, r2)) abort();
  if (message_count > 2 && !message_eq(2, r3)) abort();

  parser_free();
}

/* SCAN through every possible breaking to make sure the
 * parser can handle getting the content in any chunks that
 * might come from the socket
 */
void
test_scan (const struct message *r1, const struct message *r2, const struct message *r3)
{
  char total[80*1024] = "\0";
  char buf1[80*1024] = "\0";
  char buf2[80*1024] = "\0";
  char buf3[80*1024] = "\0";
  size_t buf1_len, buf2_len, buf3_len;
  size_t read;
  int i,j,type_both;
  int total_len, total_ops, ops, message_count;

  strcat(total, r1->raw);
  strcat(total, r2->raw);
  strcat(total, r3->raw);

  

  total_len = strlen(total);

  total_ops = 2 * (total_len - 1) * (total_len - 2) / 2;
  ops = 0 ;

  
  message_count = count_parsed_messages(3, r1, r2, r3);
  
  for (type_both = 0; type_both < 2; type_both ++ ) {
    for (j = 2; j < total_len; j ++ ) {
      for (i = 1; i < j; i ++ ) {

        if (ops % 1000 == 0)  {
          printf("\b\b\b\b%3.0f%%", 100 * (float)ops /(float)total_ops);
          fflush(stdout);
        }
        ops += 1;

        parser_init(type_both ? HTTP_BOTH : r1->type);

        buf1_len = i;
        strlncpy(buf1, sizeof(buf1), total, buf1_len);
        buf1[buf1_len] = 0;

        buf2_len = j - i;
        strlncpy(buf2, sizeof(buf1), total+i, buf2_len);
        buf2[buf2_len] = 0;

        buf3_len = total_len - j;
        strlncpy(buf3, sizeof(buf1), total+j, buf3_len);
        buf3[buf3_len] = 0;

        read = parse(buf1, buf1_len);

        if (parser->upgrade) goto test;

        if (read != buf1_len) {
          print_error(buf1, read);
          goto error;
        }

        read += parse(buf2, buf2_len);

        if (parser->upgrade) goto test;

        if (read != buf1_len + buf2_len) {
          print_error(buf2, read);
          goto error;
        }

        read += parse(buf3, buf3_len);

        if (parser->upgrade) goto test;

        if (read != buf1_len + buf2_len + buf3_len) {
          print_error(buf3, read);
          goto error;
        }

        parse(NULL, 0);

test:
        if (parser->upgrade) {
          upgrade_message_fix(total, read, 3, r1, r2, r3);
        }

        if (message_count != num_messages) {
          fprintf(stderr, "\n\nParser didn't see %d messages only %d\n",
            message_count, num_messages);
          goto error;
        }

        if (!message_eq(0, r1)) {
          fprintf(stderr, "\n\nError matching messages[0] in test_scan.\n");
          goto error;
        }

        if (message_count > 1 && !message_eq(1, r2)) {
          fprintf(stderr, "\n\nError matching messages[1] in test_scan.\n");
          goto error;
        }

        if (message_count > 2 && !message_eq(2, r3)) {
          fprintf(stderr, "\n\nError matching messages[2] in test_scan.\n");
          goto error;
        }

        parser_free();
      }
    }
  }
  puts("\b\b\b\b100%");
  return;

 error:
  fprintf(stderr, "i=%d  j=%d\n", i, j);
  fprintf(stderr, "buf1 (%u) %s\n\n", (unsigned int)buf1_len, buf1);
  fprintf(stderr, "buf2 (%u) %s\n\n", (unsigned int)buf2_len , buf2);
  fprintf(stderr, "buf3 (%u) %s\n", (unsigned int)buf3_len, buf3);
  abort();
}

// user required to free the result
// string terminated by \0
char *
create_large_chunked_message (int body_size_in_kb, const char* headers)
{
  int i;
  size_t wrote = 0;
  size_t headers_len = strlen(headers);
  size_t bufsize = headers_len + (5+1024+2)*body_size_in_kb + 6;
  char * buf = (char*) malloc(bufsize);

  memcpy(buf, headers, headers_len);
  wrote += headers_len;

  for (i = 0; i < body_size_in_kb; i++) {
    // write 1kb chunk into the body.
    memcpy(buf + wrote, "400\r\n", 5);
    wrote += 5;
    memset(buf + wrote, 'C', 1024);
    wrote += 1024;
    strcpy(buf + wrote, "\r\n");
    wrote += 2;
  }

  memcpy(buf + wrote, "0\r\n\r\n", 6);
  wrote += 6;
  assert(wrote == bufsize);

  return buf;
}

/* Verify that we can pause parsing at any of the bytes in the
 * message and still get the result that we're expecting. */
void
test_message_pause (const struct message *msg)
{
  char *buf = (char*) msg->raw;
  size_t buflen = strlen(msg->raw);
  size_t nread;

  parser_init(msg->type);

  do {
    nread = parse_pause(buf, buflen);

    // We can only set the upgrade buffer once we've gotten our message
    // completion callback.
    if (messages[0].message_complete_cb_called &&
        msg->upgrade &&
        parser->upgrade) {
      messages[0].upgrade = buf + nread;
      goto test;
    }

    if (nread < buflen) {

      // Not much do to if we failed a strict-mode check
      if (HTTP_PARSER_ERRNO(parser) == HPE_STRICT) {
        parser_free();
        return;
      }

      assert (HTTP_PARSER_ERRNO(parser) == HPE_PAUSED);
    }

    buf += nread;
    buflen -= nread;
    http_parser_pause(parser, 0);
  } while (buflen > 0);

  nread = parse_pause(NULL, 0);
  assert (nread == 0);

test:
  if (num_messages != 1) {
    printf("\n*** num_messages != 1 after testing '%s' ***\n\n", msg->name);
    abort();
  }

  if(!message_eq(0, msg)) abort();

  parser_free();
}

int
main (void)
{
  
  int i, j, k;
  int request_count;
  int response_count;
  unsigned long version;
  unsigned int major;
  unsigned int minor;
  unsigned int patch;
  const char **this_method;

  const char *all_methods[] = {
    "DELETE",
    "GET",
    "HEAD",
    "POST",
    "PUT",
    //"CONNECT", //CONNECT can't be tested like other methods, it's a tunnel
    "OPTIONS",
    "TRACE",
    "COPY",
    "LOCK",
    "MKCOL",
    "MOVE",
    "PROPFIND",
    "PROPPATCH",
    "UNLOCK",
    "REPORT",
    "MKACTIVITY",
    "CHECKOUT",
    "MERGE",
    "M-SEARCH",
    "NOTIFY",
    "SUBSCRIBE",
    "UNSUBSCRIBE",
    "PATCH",
    0 };

  const char *bad_methods[] = {
      "ASDF",
      "C******",
      "COLA",
      "GEM",
      "GETA",
      "M****",
      "MKCOLA",
      "PROPPATCHA",
      "PUN",
      "PX",
      "SA",
      "hello world",
      0 };
  const char *dumbfuck2 =
    "GET / HTTP/1.1\r\n"
    "X-SSL-Bullshit:   -----BEGIN CERTIFICATE-----\r\n"
    "\tMIIFbTCCBFWgAwIBAgICH4cwDQYJKoZIhvcNAQEFBQAwcDELMAkGA1UEBhMCVUsx\r\n"
    "\tETAPBgNVBAoTCGVTY2llbmNlMRIwEAYDVQQLEwlBdXRob3JpdHkxCzAJBgNVBAMT\r\n"
    "\tAkNBMS0wKwYJKoZIhvcNAQkBFh5jYS1vcGVyYXRvckBncmlkLXN1cHBvcnQuYWMu\r\n"
    "\tdWswHhcNMDYwNzI3MTQxMzI4WhcNMDcwNzI3MTQxMzI4WjBbMQswCQYDVQQGEwJV\r\n"
    "\tSzERMA8GA1UEChMIZVNjaWVuY2UxEzARBgNVBAsTCk1hbmNoZXN0ZXIxCzAJBgNV\r\n"
    "\tBAcTmrsogriqMWLAk1DMRcwFQYDVQQDEw5taWNoYWVsIHBhcmQYJKoZIhvcNAQEB\r\n"
    "\tBQADggEPADCCAQoCggEBANPEQBgl1IaKdSS1TbhF3hEXSl72G9J+WC/1R64fAcEF\r\n"
    "\tW51rEyFYiIeZGx/BVzwXbeBoNUK41OK65sxGuflMo5gLflbwJtHBRIEKAfVVp3YR\r\n"
    "\tgW7cMA/s/XKgL1GEC7rQw8lIZT8RApukCGqOVHSi/F1SiFlPDxuDfmdiNzL31+sL\r\n"
    "\t0iwHDdNkGjy5pyBSB8Y79dsSJtCW/iaLB0/n8Sj7HgvvZJ7x0fr+RQjYOUUfrePP\r\n"
    "\tu2MSpFyf+9BbC/aXgaZuiCvSR+8Snv3xApQY+fULK/xY8h8Ua51iXoQ5jrgu2SqR\r\n"
    "\twgA7BUi3G8LFzMBl8FRCDYGUDy7M6QaHXx1ZWIPWNKsCAwEAAaOCAiQwggIgMAwG\r\n"
    "\tA1UdEwEB/wQCMAAwEQYJYIZIAYb4QgHTTPAQDAgWgMA4GA1UdDwEB/wQEAwID6DAs\r\n"
    "\tBglghkgBhvhCAQ0EHxYdVUsgZS1TY2llbmNlIFVzZXIgQ2VydGlmaWNhdGUwHQYD\r\n"
    "\tVR0OBBYEFDTt/sf9PeMaZDHkUIldrDYMNTBZMIGaBgNVHSMEgZIwgY+AFAI4qxGj\r\n"
    "\tloCLDdMVKwiljjDastqooXSkcjBwMQswCQYDVQQGEwJVSzERMA8GA1UEChMIZVNj\r\n"
    "\taWVuY2UxEjAQBgNVBAsTCUF1dGhvcml0eTELMAkGA1UEAxMCQ0ExLTArBgkqhkiG\r\n"
    "\t9w0BCQEWHmNhLW9wZXJhdG9yQGdyaWQtc3VwcG9ydC5hYy51a4IBADApBgNVHRIE\r\n"
    "\tIjAggR5jYS1vcGVyYXRvckBncmlkLXN1cHBvcnQuYWMudWswGQYDVR0gBBIwEDAO\r\n"
    "\tBgwrBgEEAdkvAQEBAQYwPQYJYIZIAYb4QgEEBDAWLmh0dHA6Ly9jYS5ncmlkLXN1\r\n"
    "\tcHBvcnQuYWMudmT4sopwqlBWsvcHViL2NybC9jYWNybC5jcmwwPQYJYIZIAYb4QgEDBDAWLmh0\r\n"
    "\tdHA6Ly9jYS5ncmlkLXN1cHBvcnQuYWMudWsvcHViL2NybC9jYWNybC5jcmwwPwYD\r\n"
    "\tVR0fBDgwNjA0oDKgMIYuaHR0cDovL2NhLmdyaWQt5hYy51ay9wdWIv\r\n"
    "\tY3JsL2NhY3JsLmNybDANBgkqhkiG9w0BAQUFAAOCAQEAS/U4iiooBENGW/Hwmmd3\r\n"
    "\tXCy6Zrt08YjKCzGNjorT98g8uGsqYjSxv/hmi0qlnlHs+k/3Iobc3LjS5AMYr5L8\r\n"
    "\tUO7OSkgFFlLHQyC9JzPfmLCAugvzEbyv4Olnsr8hbxF1MbKZoQxUZtMVu29wjfXk\r\n"
    "\thTeApBv7eaKCWpSp7MCbvgzm74izKhu3vlDk9w6qVrxePfGgpKPqfHiOoGhFnbTK\r\n"
    "\twTC6o2xq5y0qZ03JonF7OJspEd3I5zKY3E+ov7/ZhW6DqT8UFvsAdjvQbXyhV8Eu\r\n"
    "\tYhixw1aKEPzNjNowuIseVogKOLXxWI5vAi5HgXdS0/ES5gDGsABo4fqovUKlgop3\r\n"
    "\tRA==\r\n"
    "\t-----END CERTIFICATE-----\r\n"
    "\r\n";

#ifdef _MSC_VER
  /* Disable the "application crashed" popup. */
  SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);

  _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_DEBUG);
  _CrtSetReportMode(_CRT_ERROR, _CRTDBG_MODE_DEBUG);

#endif

  parser = NULL;

  version = http_parser_version();
  major = (version >> 16) & 255;
  minor = (version >> 8) & 255;
  patch = version & 255;
  printf("http_parser v%u.%u.%u (0x%06lx)\n", major, minor, patch, version);

  printf("sizeof(http_parser) = %u\n", (unsigned int)sizeof(http_parser));

#ifdef TEST_CASES
  for (request_count = 0; requests[request_count].name; request_count++);
  for (response_count = 0; responses[response_count].name; response_count++);
#endif

  //// API
  test_preserve_data();
  test_parse_url();
  test_method_str();

  //// OVERFLOW CONDITIONS

  test_header_overflow_error(HTTP_REQUEST);
  test_no_overflow_long_body(HTTP_REQUEST, 1000);
  test_no_overflow_long_body(HTTP_REQUEST, 100000);

  test_header_overflow_error(HTTP_RESPONSE);
  test_no_overflow_long_body(HTTP_RESPONSE, 1000);
  test_no_overflow_long_body(HTTP_RESPONSE, 100000);

  test_header_content_length_overflow_error();
  test_chunk_content_length_overflow_error();

  //// RESPONSES
#ifdef TEST_CASES
  for (i = 0; i < response_count; i++) {
    test_message(&responses[i]);
  }

  for (i = 0; i < response_count; i++) {
    test_message_pause(&responses[i]);
  }

  for (i = 0; i < response_count; i++) {
    if (!responses[i].should_keep_alive) continue;
    for (j = 0; j < response_count; j++) {
      if (!responses[j].should_keep_alive) continue;
      for (k = 0; k < response_count; k++) {
        test_multiple3(&responses[i], &responses[j], &responses[k]);
      }
    }
  }


  test_message_count_body(&responses[NO_HEADERS_NO_BODY_404]);
  test_message_count_body(&responses[TRAILING_SPACE_ON_CHUNKED_BODY]);
#endif

  // test very large chunked response
  {
    char * msg = create_large_chunked_message(31337,
      "HTTP/1.0 200 OK\r\n"
      "Transfer-Encoding: chunked\r\n"
      "Content-Type: text/plain\r\n"
      "\r\n");
    struct message large_chunked;
    memset(&large_chunked, 0, sizeof(large_chunked));
    large_chunked.name = "large chunked";
    large_chunked.type = HTTP_RESPONSE;
    large_chunked.raw = msg;
    
    large_chunked.should_keep_alive= FALSE;
    large_chunked.message_complete_on_eof= FALSE;
    large_chunked.http_major= 1;
    large_chunked.http_minor= 0;
    large_chunked.status_code= 200;
    memcpy(large_chunked.response_status, "OK", 3);
    large_chunked.num_headers= 2;
    strcpy(large_chunked.headers[0][0], "Transfer-Encoding");
    strcpy(large_chunked.headers[0][1], "chunked");
    strcpy(large_chunked.headers[1][0], "Content-Type");
    strcpy(large_chunked.headers[1][1], "text/plain");
    large_chunked.body_size= 31337*1024;
    test_message_count_body(&large_chunked);
    free(msg);
  }


#ifdef TEST_CASES
  printf("response scan 1/2      ");
  test_scan( &responses[TRAILING_SPACE_ON_CHUNKED_BODY]
           , &responses[NO_BODY_HTTP10_KA_204]
           , &responses[NO_REASON_PHRASE]
           );

  printf("response scan 2/2      ");
  test_scan( &responses[BONJOUR_MADAME_FR]
           , &responses[UNDERSTORE_HEADER_KEY]
           , &responses[NO_CARRIAGE_RET]
           );

  puts("responses okay");
#endif

  /// REQUESTS

  test_simple("GET / HTP/1.1\r\n\r\n", HPE_INVALID_VERSION);

  // Well-formed but incomplete
  test_simple("GET / HTTP/1.1\r\n"
              "Content-Type: text/plain\r\n"
              "Content-Length: 6\r\n"
              "\r\n"
              "fooba",
              HPE_OK);

    
  for (this_method = all_methods; *this_method; this_method++) {
    char buf[200];
    sprintf(buf, "%s / HTTP/1.1\r\n\r\n", *this_method);
    test_simple(buf, HPE_OK);
  }

  
  for (this_method = bad_methods; *this_method; this_method++) {
    char buf[200];
    sprintf(buf, "%s / HTTP/1.1\r\n\r\n", *this_method);
    test_simple(buf, HPE_INVALID_METHOD);
  }

  // illegal header field name line folding
  test_simple("GET / HTTP/1.1\r\n"
              "name\r\n"
              " : value\r\n"
              "\r\n",
              HPE_INVALID_HEADER_TOKEN);

  
  test_simple(dumbfuck2, HPE_OK);

#if 0
  // NOTE(Wed Nov 18 11:57:27 CET 2009) this seems okay. we just read body
  // until EOF.
  //
  // no content-length
  // error if there is a body without content length
  const char *bad_get_no_headers_no_body = "GET /bad_get_no_headers_no_body/world HTTP/1.1\r\n"
                                           "Accept: */*\r\n"
                                           "\r\n"
                                           "HELLO";
  test_simple(bad_get_no_headers_no_body, 0);
#endif
  /* TODO sending junk and large headers gets rejected */


#ifdef TEST_CASES
  /* check to make sure our predefined requests are okay */
  for (i = 0; requests[i].name; i++) {
    test_message(&requests[i]);
  }

  for (i = 0; i < request_count; i++) {
    test_message_pause(&requests[i]);
  }

  for (i = 0; i < request_count; i++) {
    if (!requests[i].should_keep_alive) continue;
    for (j = 0; j < request_count; j++) {
      if (!requests[j].should_keep_alive) continue;
      for (k = 0; k < request_count; k++) {
        test_multiple3(&requests[i], &requests[j], &requests[k]);
      }
    }
  }

  printf("request scan 1/4      ");
  test_scan( &requests[GET_NO_HEADERS_NO_BODY]
           , &requests[GET_ONE_HEADER_NO_BODY]
           , &requests[GET_NO_HEADERS_NO_BODY]
           );

  printf("request scan 2/4      ");
  test_scan( &requests[POST_CHUNKED_ALL_YOUR_BASE]
           , &requests[POST_IDENTITY_BODY_WORLD]
           , &requests[GET_FUNKY_CONTENT_LENGTH]
           );

  printf("request scan 3/4      ");
  test_scan( &requests[TWO_CHUNKS_MULT_ZERO_END]
           , &requests[CHUNKED_W_TRAILING_HEADERS]
           , &requests[CHUNKED_W_BULLSHIT_AFTER_LENGTH]
           );

  printf("request scan 4/4      ");
  test_scan( &requests[QUERY_URL_WITH_QUESTION_MARK_GET]
           , &requests[PREFIX_NEWLINE_GET ]
           , &requests[CONNECT_REQUEST]
           );
#endif
  puts("requests okay");

  return 0;
}
