
#include <ngx_config.h>
#include <ngx_core.h>



extern ngx_module_t  ngx_core_module;
extern ngx_module_t  ngx_errlog_module;
extern ngx_module_t  ngx_conf_module;
extern ngx_module_t  ngx_openssl_module;
extern ngx_module_t  ngx_regex_module;
extern ngx_module_t  ngx_events_module;
extern ngx_module_t  ngx_event_core_module;
extern ngx_module_t  ngx_epoll_module;
extern ngx_module_t  ngx_http_module;
extern ngx_module_t  ngx_http_core_module;
extern ngx_module_t  ngx_http_log_module;
extern ngx_module_t  ngx_http_upstream_module;
extern ngx_module_t  ngx_http_static_module;
extern ngx_module_t  ngx_http_gzip_static_module;
extern ngx_module_t  ngx_http_autoindex_module;
extern ngx_module_t  ngx_http_index_module;
extern ngx_module_t  ngx_http_mirror_module;
extern ngx_module_t  ngx_http_try_files_module;
extern ngx_module_t  ngx_http_auth_basic_module;
extern ngx_module_t  ngx_http_access_module;
extern ngx_module_t  ngx_http_limit_conn_module;
extern ngx_module_t  ngx_http_limit_req_module;
extern ngx_module_t  ngx_http_realip_module;
extern ngx_module_t  ngx_http_geo_module;
extern ngx_module_t  ngx_http_map_module;
extern ngx_module_t  ngx_http_split_clients_module;
extern ngx_module_t  ngx_http_referer_module;
extern ngx_module_t  ngx_http_rewrite_module;
extern ngx_module_t  ngx_http_ssl_module;
extern ngx_module_t  ngx_http_proxy_module;
extern ngx_module_t  ngx_http_fastcgi_module;
extern ngx_module_t  ngx_http_uwsgi_module;
extern ngx_module_t  ngx_http_scgi_module;
extern ngx_module_t  ngx_http_memcached_module;
extern ngx_module_t  ngx_http_empty_gif_module;
extern ngx_module_t  ngx_http_browser_module;
extern ngx_module_t  ngx_http_upstream_hash_module;
extern ngx_module_t  ngx_http_upstream_ip_hash_module;
extern ngx_module_t  ngx_http_upstream_least_conn_module;
extern ngx_module_t  ngx_http_upstream_random_module;
extern ngx_module_t  ngx_http_upstream_keepalive_module;
extern ngx_module_t  ngx_http_upstream_zone_module;
extern ngx_module_t  ngx_http_stub_status_module;
extern ngx_module_t  ngx_http_hello_world_module;
extern ngx_module_t  ngx_http_write_filter_module;
extern ngx_module_t  ngx_http_header_filter_module;
extern ngx_module_t  ngx_http_chunked_filter_module;
extern ngx_module_t  ngx_http_range_header_filter_module;
extern ngx_module_t  ngx_http_gzip_filter_module;
extern ngx_module_t  ngx_http_postpone_filter_module;
extern ngx_module_t  ngx_http_ssi_filter_module;
extern ngx_module_t  ngx_http_charset_filter_module;
extern ngx_module_t  ngx_http_userid_filter_module;
extern ngx_module_t  ngx_http_headers_filter_module;
extern ngx_module_t  ngx_http_hello_filter_module;
extern ngx_module_t  ngx_http_copy_filter_module;
extern ngx_module_t  ngx_http_range_body_filter_module;
extern ngx_module_t  ngx_http_not_modified_filter_module;

ngx_module_t *ngx_modules[] = {
	// ȫ��coreģ��
    &ngx_core_module,
    &ngx_errlog_module,
    &ngx_conf_module,
    &ngx_openssl_module, //--with-http_ssl_module

	// ����ģ��
    &ngx_regex_module,

	// eventģ��
    &ngx_events_module,
    &ngx_event_core_module,
    &ngx_epoll_module,

	// httpģ��
    &ngx_http_module,
    &ngx_http_core_module,
    &ngx_http_log_module,
    &ngx_http_upstream_module,

	// http handlerģ��
    &ngx_http_static_module,
    &ngx_http_gzip_static_module, //--with-http_gzip_static_module
    &ngx_http_autoindex_module,
    &ngx_http_index_module,
    &ngx_http_mirror_module,
    &ngx_http_try_files_module,
    &ngx_http_auth_basic_module,
    &ngx_http_access_module,
    &ngx_http_limit_conn_module,
    &ngx_http_limit_req_module,
    &ngx_http_realip_module, //--with-http_realip_module
    &ngx_http_geo_module,
    &ngx_http_map_module,
    &ngx_http_split_clients_module,
    &ngx_http_referer_module,
    &ngx_http_rewrite_module,
    &ngx_http_ssl_module,
    &ngx_http_proxy_module,
    &ngx_http_fastcgi_module,
    &ngx_http_uwsgi_module,
    &ngx_http_scgi_module,
    &ngx_http_memcached_module,
    &ngx_http_empty_gif_module,
    &ngx_http_browser_module,
    &ngx_http_upstream_hash_module,
    &ngx_http_upstream_ip_hash_module,
    &ngx_http_upstream_least_conn_module,
    &ngx_http_upstream_random_module,
    &ngx_http_upstream_keepalive_module,
    &ngx_http_upstream_zone_module,
    &ngx_http_stub_status_module, //--with-http_stub_status_module
    //�˴��ǵ�����handlerģ��
    &ngx_http_hello_world_module,

	//========������filterģ��========//
    //filterģ���ǵ���ִ�У�ngx_http_not_modified_filter_module����ִ�Уngx_http_write_filter_module����ִ��
    //ngx_http_top_header_filter��ngx_http_top_body_filterʵ������filter�����ͷ��㣬��������filterģ��ʱ������ӵ�����ͷ���������յ���ִ����Щfilterģ��
    //������ģ��ᱻNginxע����ngx_http_copy_filter_module֮��ngx_http_headers_filter_module֮ǰ�������趨��ԭ����Ϊ��ȷ��һЩģ�����gzip filter��chunked filter��copy filter������filter���Ŀ�ͷ��β��
    &ngx_http_write_filter_module,			/* ���һ��body filter���������ⷢ������ */
    &ngx_http_header_filter_module,			/* ���һ��header filter���������ڴ���ƴ�ӳ�������http��Ӧͷ��
                                               ������ngx_http_write_filter���� */
    &ngx_http_chunked_filter_module,		/* ����Ӧͷ��û��content_lengthͷ������ǿ�ƶ����ӣ�����http 1.1��
                                               �����chunked���루http 1.1) */
    &ngx_http_range_header_filter_module,	/* header filter��������rangeͷ */
    &ngx_http_gzip_filter_module,			/* ֧����ʽ������ѹ�� */
    &ngx_http_postpone_filter_module,		/* body filter������������������������ݵ����˳�� */
    &ngx_http_ssi_filter_module,			/* ֧�ֹ���SSI���󣬲��÷���������ķ�ʽ��ȥ��ȡinclude�������ļ� */
    &ngx_http_charset_filter_module,		/* ֧�����charset��Ҳ֧�ֽ����ݴ�һ���ַ���ת��������һ���ַ��� */
    &ngx_http_userid_filter_module,			/* ֧�����ͳ���õ�ʶ���û���cookie */
    &ngx_http_headers_filter_module,		/* ֧������expire��Cache-controlͷ��֧������������Ƶ�ͷ */
    // ������filterģ��start
    &ngx_http_hello_filter_module,			/* ������filterģ��*/
    // ������filterģ��end
    &ngx_http_copy_filter_module,			/* �����������¸�����������е�ĳЩ�ڵ�
                                              �����罫in_file�Ľڵ���ļ����������Ƶ��µĽڵ㣩������������filter
                                               ���д��� */
    &ngx_http_range_body_filter_module,		/* body filter��֧��range���ܣ�����������range����
                                               �Ǿ�ֻ����range�����һ������ */
    &ngx_http_not_modified_filter_module,	/* ��������if-modified-since���ڻظ���last-modifiedֵ��
                                               ˵���ظ�û�б仯��������лظ������ݣ�����304 */
    NULL
};

char *ngx_module_names[] = {
    "ngx_core_module",
    "ngx_errlog_module",
    "ngx_conf_module",
    "ngx_openssl_module",
    "ngx_regex_module",
    "ngx_events_module",
    "ngx_event_core_module",
    "ngx_epoll_module",
    "ngx_http_module",
    "ngx_http_core_module",
    "ngx_http_log_module",
    "ngx_http_upstream_module",
    "ngx_http_static_module",
    "ngx_http_gzip_static_module",
    "ngx_http_autoindex_module",
    "ngx_http_index_module",
    "ngx_http_mirror_module",
    "ngx_http_try_files_module",
    "ngx_http_auth_basic_module",
    "ngx_http_access_module",
    "ngx_http_limit_conn_module",
    "ngx_http_limit_req_module",
    "ngx_http_realip_module",
    "ngx_http_geo_module",
    "ngx_http_map_module",
    "ngx_http_split_clients_module",
    "ngx_http_referer_module",
    "ngx_http_rewrite_module",
    "ngx_http_ssl_module",
    "ngx_http_proxy_module",
    "ngx_http_fastcgi_module",
    "ngx_http_uwsgi_module",
    "ngx_http_scgi_module",
    "ngx_http_memcached_module",
    "ngx_http_empty_gif_module",
    "ngx_http_browser_module",
    "ngx_http_upstream_hash_module",
    "ngx_http_upstream_ip_hash_module",
    "ngx_http_upstream_least_conn_module",
    "ngx_http_upstream_random_module",
    "ngx_http_upstream_keepalive_module",
    "ngx_http_upstream_zone_module",
    "ngx_http_stub_status_module",
    "ngx_http_hello_world_module",
    "ngx_http_write_filter_module",
    "ngx_http_header_filter_module",
    "ngx_http_chunked_filter_module",
    "ngx_http_range_header_filter_module",
    "ngx_http_gzip_filter_module",
    "ngx_http_postpone_filter_module",
    "ngx_http_ssi_filter_module",
    "ngx_http_charset_filter_module",
    "ngx_http_userid_filter_module",
    "ngx_http_headers_filter_module",
    "ngx_http_hello_filter_module",
    "ngx_http_copy_filter_module",
    "ngx_http_range_body_filter_module",
    "ngx_http_not_modified_filter_module",
    NULL
};

