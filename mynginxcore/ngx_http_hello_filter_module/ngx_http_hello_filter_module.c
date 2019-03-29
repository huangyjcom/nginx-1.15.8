/*ngx_http_hello_filter_module.c*/

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


/*用static修饰只在本文件生效，因此允许所有的过滤模块都有自己的这两个指针*/
static ngx_http_output_header_filter_pt ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


/*初始化方法，将过滤模块插入到链表头部*/
static ngx_int_t
ngx_http_hello_filter_init(ngx_conf_t *cf);


/*头部处理方法*/
static ngx_int_t
ngx_http_hello_filter_header_filter(ngx_http_request_t *r);

/*包体处理方法*/
static ngx_int_t
ngx_http_hello_filter_body_filter(ngx_http_request_t *r, ngx_chain_t *in);


typedef struct
{
    ngx_flag_t enable;
}ngx_http_hello_filter_conf_t;

/*请求上下文*/
typedef struct
{
    ngx_int_t add_prefix;
}ngx_http_hello_filter_ctx_t;

/*在包体中添加的前缀*/
static ngx_str_t filter_prefix=ngx_string("[my filter prefix]");



/*处理感兴趣的配置项*/
static ngx_command_t ngx_http_hello_filter_commands[]=
{
    {
        ngx_string("add_prefix"), //配置项名称
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_FLAG,//配置项只能携带一个参数并且是on或者off
        ngx_conf_set_flag_slot,//使用nginx自带方法,参数on/off
        NGX_HTTP_LOC_CONF_OFFSET,//使用create_loc_conf方法产生的结构体来存储
        //解析出来的配置项参数
        offsetof(ngx_http_hello_filter_conf_t, enable),//on/off
        NULL
    },
    ngx_null_command //
};

static void* ngx_http_hello_filter_create_conf(ngx_conf_t *cf);
static char*
ngx_http_hello_filter_merge_conf(ngx_conf_t *cf,void*parent,void*child);

/*模块上下文*/
static ngx_http_module_t ngx_http_hello_filter_module_ctx=
{
    NULL,                                  /* preconfiguration方法  */
    ngx_http_hello_filter_init,            /* postconfiguration方法 */

    NULL,                                  /*create_main_conf 方法 */
    NULL,                                  /* init_main_conf方法 */

    NULL,                                  /* create_srv_conf方法 */
    NULL,                                  /* merge_srv_conf方法 */

    ngx_http_hello_filter_create_conf,    /* create_loc_conf方法 */
    ngx_http_hello_filter_merge_conf      /*merge_loc_conf方法*/
};


/*定义过滤模块,ngx_module_t结构体实例化*/
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

    //创建存储配置项的结构体
    mycf = (ngx_http_hello_filter_conf_t  *)ngx_pcalloc(cf->pool, sizeof(ngx_http_hello_filter_conf_t));
    if (mycf == NULL)
    {
        return NULL;
    }

    //ngx_flat_t类型的变量，如果使用预设函数ngx_conf_set_flag_slot
    //解析配置项参数，必须初始化为NGX_CONF_UNSET
    mycf->enable = NGX_CONF_UNSET;
    return mycf;
}

static char*
ngx_http_hello_filter_merge_conf(ngx_conf_t *cf,void*parent,void*child)
{
    ngx_http_hello_filter_conf_t *prev = (ngx_http_hello_filter_conf_t *)parent;
    ngx_http_hello_filter_conf_t *conf = (ngx_http_hello_filter_conf_t *)child;

    //合并ngx_flat_t类型的配置项enable
    ngx_conf_merge_value(conf->enable, prev->enable, 0);

    return NGX_CONF_OK;

}



/*初始化方法*/
static ngx_int_t
ngx_http_hello_filter_init(ngx_conf_t*cf)
{

    //插入到头部处理方法链表的首部
    ngx_http_next_header_filter=ngx_http_top_header_filter;
    ngx_http_top_header_filter=ngx_http_hello_filter_header_filter;
    //插入到包体处理方法链表的首部
    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_hello_filter_body_filter;
    return NGX_OK;
}

/*头部处理方法*/
static ngx_int_t
ngx_http_hello_filter_header_filter(ngx_http_request_t *r)
{
    ngx_http_hello_filter_ctx_t *ctx;
    ngx_http_hello_filter_conf_t *conf;
	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "ngx_http_hello_filter_header_filter");
    //如果不是返回成功，这时是不需要理会是否加前缀的，
    //直接交由下一个过滤模块
    //处理响应码非200的情形
    if (r->headers_out.status != NGX_HTTP_OK)
    {
        return ngx_http_next_header_filter(r);
    }


    /*获取http上下文*/
    ctx = ngx_http_get_module_ctx(r, ngx_http_hello_filter_module);

    if(ctx)
    {
        //该请求的上下文已经存在，这说明
        // ngx_http_hello_filter_header_filter已经被调用过1次，
        //直接交由下一个过滤模块处理
        return ngx_http_next_header_filter(r);
    }


    //获取存储配置项参数的结构体
    conf = ngx_http_get_module_loc_conf(r, ngx_http_hello_filter_module);

    //如果enable成员为0，也就是配置文件中没有配置add_prefix配置项，
    //或者add_prefix配置项的参数值是off，这时直接交由下一个过滤模块处理
    if (conf->enable == 0)
    {
        return ngx_http_next_header_filter(r);
    }

    //conf->enable==1
    //构造http上下文结构体ngx_http_hello_filter_ctx_t
    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_hello_filter_ctx_t));
    if(NULL==ctx)
    {
        return NGX_ERROR;
    }
    ctx->add_prefix=0;
    ngx_http_set_ctx(r,ctx,ngx_http_hello_filter_module);

    //只处理Content-Type是"text/plain"类型的http响应
    if (r->headers_out.content_type.len >= sizeof("text/html") - 1
        && ngx_strncasecmp(r->headers_out.content_type.data, (u_char *) "text/html", sizeof("text/html") - 1) == 0)
    {
        ctx->add_prefix=1;
        if(r->headers_out.content_length_n > 0)
        {
            r->headers_out.content_length_n+=filter_prefix.len;
        }

    }

    //交由下一个过滤模块继续处理
    return ngx_http_next_header_filter(r);
}

/*包体处理方法*/
static ngx_int_t
ngx_http_hello_filter_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_http_hello_filter_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_hello_filter_module);

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "ngx_http_hello_filter_body_filter");

    //如果获取不到上下文，或者上下文结构体中的add_prefix为0或者2时，
    //都不会添加前缀，这时直接交给下一个http过滤模块处理
    if (ctx == NULL || ctx->add_prefix != 1)
    {
        return ngx_http_next_body_filter(r, in);
    }

    //将add_prefix设置为2，这样即使ngx_http_hello_filter_body_filter
    //再次回调时，也不会重复添加前缀
    ctx->add_prefix = 2;
    //从请求的内存池中分配内存，用于存储字符串前缀
    ngx_buf_t* b = ngx_create_temp_buf(r->pool, filter_prefix.len);

    //将ngx_buf_t中的指针正确地指向filter_prefix字符串
    b->start = b->pos = filter_prefix.data;
    b->last = b->pos + filter_prefix.len;

    //从请求的内存池中生成ngx_chain_t链表，将刚分配的ngx_buf_t设置到
    //其buf成员中，并将它添加到原先待发送的http包体前面
    ngx_chain_t *cl = ngx_alloc_chain_link(r->pool);
    /*note: in表示原来待发送的包体*/
    cl->buf = b;
    cl->next = in;

    //调用下一个模块的http包体处理方法，注意这时传入的是新生成的cl链表
    return ngx_http_next_body_filter(r, cl);
}

