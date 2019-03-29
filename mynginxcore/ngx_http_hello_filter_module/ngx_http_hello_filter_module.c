/*ngx_http_hello_filter_module.c*/

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


/*��static����ֻ�ڱ��ļ���Ч������������еĹ���ģ�鶼���Լ���������ָ��*/
static ngx_http_output_header_filter_pt ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


/*��ʼ��������������ģ����뵽����ͷ��*/
static ngx_int_t
ngx_http_hello_filter_init(ngx_conf_t *cf);


/*ͷ��������*/
static ngx_int_t
ngx_http_hello_filter_header_filter(ngx_http_request_t *r);

/*���崦����*/
static ngx_int_t
ngx_http_hello_filter_body_filter(ngx_http_request_t *r, ngx_chain_t *in);


typedef struct
{
    ngx_flag_t enable;
}ngx_http_hello_filter_conf_t;

/*����������*/
typedef struct
{
    ngx_int_t add_prefix;
}ngx_http_hello_filter_ctx_t;

/*�ڰ�������ӵ�ǰ׺*/
static ngx_str_t filter_prefix=ngx_string("[my filter prefix]");



/*�������Ȥ��������*/
static ngx_command_t ngx_http_hello_filter_commands[]=
{
    {
        ngx_string("add_prefix"), //����������
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_FLAG,//������ֻ��Я��һ������������on����off
        ngx_conf_set_flag_slot,//ʹ��nginx�Դ�����,����on/off
        NGX_HTTP_LOC_CONF_OFFSET,//ʹ��create_loc_conf���������Ľṹ�����洢
        //�������������������
        offsetof(ngx_http_hello_filter_conf_t, enable),//on/off
        NULL
    },
    ngx_null_command //
};

static void* ngx_http_hello_filter_create_conf(ngx_conf_t *cf);
static char*
ngx_http_hello_filter_merge_conf(ngx_conf_t *cf,void*parent,void*child);

/*ģ��������*/
static ngx_http_module_t ngx_http_hello_filter_module_ctx=
{
    NULL,                                  /* preconfiguration����  */
    ngx_http_hello_filter_init,            /* postconfiguration���� */

    NULL,                                  /*create_main_conf ���� */
    NULL,                                  /* init_main_conf���� */

    NULL,                                  /* create_srv_conf���� */
    NULL,                                  /* merge_srv_conf���� */

    ngx_http_hello_filter_create_conf,    /* create_loc_conf���� */
    ngx_http_hello_filter_merge_conf      /*merge_loc_conf����*/
};


/*�������ģ��,ngx_module_t�ṹ��ʵ����*/
ngx_module_t ngx_http_hello_filter_module =
{
    NGX_MODULE_V1,                 /*Macro*/
    &ngx_http_hello_filter_module_ctx,         /*module context*/
    ngx_http_hello_filter_commands,            /*module directives*/
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING                  /*Macro*/
};


static void* ngx_http_hello_filter_create_conf(ngx_conf_t *cf)
{
    ngx_http_hello_filter_conf_t  *mycf;

    //�����洢������Ľṹ��
    mycf = (ngx_http_hello_filter_conf_t  *)ngx_pcalloc(cf->pool, sizeof(ngx_http_hello_filter_conf_t));
    if (mycf == NULL)
    {
        return NULL;
    }

    //ngx_flat_t���͵ı��������ʹ��Ԥ�躯��ngx_conf_set_flag_slot
    //��������������������ʼ��ΪNGX_CONF_UNSET
    mycf->enable = NGX_CONF_UNSET;
    return mycf;
}

static char*
ngx_http_hello_filter_merge_conf(ngx_conf_t *cf,void*parent,void*child)
{
    ngx_http_hello_filter_conf_t *prev = (ngx_http_hello_filter_conf_t *)parent;
    ngx_http_hello_filter_conf_t *conf = (ngx_http_hello_filter_conf_t *)child;

    //�ϲ�ngx_flat_t���͵�������enable
    ngx_conf_merge_value(conf->enable, prev->enable, 0);

    return NGX_CONF_OK;

}



/*��ʼ������*/
static ngx_int_t
ngx_http_hello_filter_init(ngx_conf_t*cf)
{

    //���뵽ͷ��������������ײ�
    ngx_http_next_header_filter=ngx_http_top_header_filter;
    ngx_http_top_header_filter=ngx_http_hello_filter_header_filter;
    //���뵽���崦����������ײ�
    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_hello_filter_body_filter;
    return NGX_OK;
}

/*ͷ��������*/
static ngx_int_t
ngx_http_hello_filter_header_filter(ngx_http_request_t *r)
{
    ngx_http_hello_filter_ctx_t *ctx;
    ngx_http_hello_filter_conf_t *conf;
	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "ngx_http_hello_filter_header_filter");
    //������Ƿ��سɹ�����ʱ�ǲ���Ҫ����Ƿ��ǰ׺�ģ�
    //ֱ�ӽ�����һ������ģ��
    //������Ӧ���200������
    if (r->headers_out.status != NGX_HTTP_OK)
    {
        return ngx_http_next_header_filter(r);
    }


    /*��ȡhttp������*/
    ctx = ngx_http_get_module_ctx(r, ngx_http_hello_filter_module);

    if(ctx)
    {
        //��������������Ѿ����ڣ���˵��
        // ngx_http_hello_filter_header_filter�Ѿ������ù�1�Σ�
        //ֱ�ӽ�����һ������ģ�鴦��
        return ngx_http_next_header_filter(r);
    }


    //��ȡ�洢����������Ľṹ��
    conf = ngx_http_get_module_loc_conf(r, ngx_http_hello_filter_module);

    //���enable��ԱΪ0��Ҳ���������ļ���û������add_prefix�����
    //����add_prefix������Ĳ���ֵ��off����ʱֱ�ӽ�����һ������ģ�鴦��
    if (conf->enable == 0)
    {
        return ngx_http_next_header_filter(r);
    }

    //conf->enable==1
    //����http�����Ľṹ��ngx_http_hello_filter_ctx_t
    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_hello_filter_ctx_t));
    if(NULL==ctx)
    {
        return NGX_ERROR;
    }
    ctx->add_prefix=0;
    ngx_http_set_ctx(r,ctx,ngx_http_hello_filter_module);

    //ֻ����Content-Type��"text/plain"���͵�http��Ӧ
    if (r->headers_out.content_type.len >= sizeof("text/html") - 1
        && ngx_strncasecmp(r->headers_out.content_type.data, (u_char *) "text/html", sizeof("text/html") - 1) == 0)
    {
        ctx->add_prefix=1;
        if(r->headers_out.content_length_n > 0)
        {
            r->headers_out.content_length_n+=filter_prefix.len;
        }

    }

    //������һ������ģ���������
    return ngx_http_next_header_filter(r);
}

/*���崦����*/
static ngx_int_t
ngx_http_hello_filter_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_http_hello_filter_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_hello_filter_module);

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "ngx_http_hello_filter_body_filter");

    //�����ȡ���������ģ����������Ľṹ���е�add_prefixΪ0����2ʱ��
    //���������ǰ׺����ʱֱ�ӽ�����һ��http����ģ�鴦��
    if (ctx == NULL || ctx->add_prefix != 1)
    {
        return ngx_http_next_body_filter(r, in);
    }

    //��add_prefix����Ϊ2��������ʹngx_http_hello_filter_body_filter
    //�ٴλص�ʱ��Ҳ�����ظ����ǰ׺
    ctx->add_prefix = 2;
    //��������ڴ���з����ڴ棬���ڴ洢�ַ���ǰ׺
    ngx_buf_t* b = ngx_create_temp_buf(r->pool, filter_prefix.len);

    //��ngx_buf_t�е�ָ����ȷ��ָ��filter_prefix�ַ���
    b->start = b->pos = filter_prefix.data;
    b->last = b->pos + filter_prefix.len;

    //��������ڴ��������ngx_chain_t�������շ����ngx_buf_t���õ�
    //��buf��Ա�У���������ӵ�ԭ�ȴ����͵�http����ǰ��
    ngx_chain_t *cl = ngx_alloc_chain_link(r->pool);
    /*note: in��ʾԭ�������͵İ���*/
    cl->buf = b;
    cl->next = in;

    //������һ��ģ���http���崦������ע����ʱ������������ɵ�cl����
    return ngx_http_next_body_filter(r, cl);
}

