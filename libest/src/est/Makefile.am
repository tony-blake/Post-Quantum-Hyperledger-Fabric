lib_LTLIBRARIES = libest.la
AM_CFLAGS = -I$(SSL_CFLAGS) -I../.. -I$(SAFEC_CFLAGS)/include $(LIBCURL_CFLAGS)
libest_la_LDFLAGS = -release $(PACKAGE_VERSION) 
libest_la_SOURCES = est.c est_client.c est_server.c est_server_http.c \
                    est_client_alt_csr.c est_client_alt_cert.c est_server_alt.c \
                    est_proxy.c est_client_http.c est_ossl_util.c est_client_proxy.c

libest_la_LIBADD = $(SAFEC_LDFLAGS)
library_includedir=$(includedir)/est
library_include_HEADERS = est.h
EXTRA_DIST = est_locl.h est_ossl_util.h est_server.h est_server_http.h est_client_proxy.h est_sock_compat.h
