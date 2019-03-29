
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_BUF_H_INCLUDED_
#define _NGX_BUF_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef void *            ngx_buf_tag_t;

typedef struct ngx_buf_s  ngx_buf_t;

struct ngx_buf_s {
    u_char          *pos;//��buf��ָ����������ڴ����ʱ��posָ�����������ݿ�ʼ��λ��
    u_char          *last;//��buf��ָ����������ڴ����ʱ��lastָ�����������ݽ�����λ��
    off_t            file_pos;//��buf��ָ������������ļ����ʱ��file_posָ�����������ݵĿ�ʼλ�����ļ��е�ƫ����
    off_t            file_last;//��buf��ָ������������ļ����ʱ��file_lastָ�����������ݵĽ���λ�����ļ��е�ƫ����

	//��buf��ָ����������ڴ����ʱ����һ�����ڴ���������ݿ��ܱ������ڶ��buf��(������ĳ�������м���������������ݣ���һ�����ݾ���Ҫ����ֿ�)��
	//��ô��Щbuf�е�start��end��ָ����һ���ڴ�Ŀ�ʼ��ַ�ͽ�����ַ����pos��lastָ��buf��ʵ�ʰ��������ݵĿ�ʼ�ͽ�β
    u_char          *start;         /* start of buffer */
    u_char          *end;           /* end of buffer */
    ngx_buf_tag_t    tag;//ʵ������һ��void*���͵�ָ�룬ʹ���߿��Թ�������Ķ�����ȥ��ֻҪ��ʹ����������
    ngx_file_t      *file;//��buf���������������ļ���ʱ��file�ֶ�ָ���Ӧ���ļ�����
    ngx_buf_t       *shadow;//�����buf����copy������һ��buf�������ֶε�ʱ����ô������bufָ���ʵ������ͬһ���ڴ棬������ͬһ���ļ���ͬһ���֣�
    						//��ʱ������buf��shadow�ֶζ���ָ��Է��ġ���ô��������������buf�����ͷŵ�ʱ�򣬾���Ҫʹ�����ر�С�ģ��������������ͷţ�Ҫ��ǰ���Ǻã���������Դ�Ķ���ͷţ����ܻ���ɳ��������


    /* the buf's content could be changed */
    unsigned         temporary:1;//Ϊ1ʱ��ʾ��buf����������������һ���û��������ڴ���У����ҿ��Ա���filter����Ĺ����н��б�����������������

    /*
     * the buf's content is in a memory cache or in a read only memory
     * and must not be changed
     */
    unsigned         memory:1;//Ϊ1ʱ��ʾ��buf�����������������ڴ��У�������Щ����ȴ���ܱ����д����filter���б��

    /* the buf's content is mmap()ed and must not be changed */
    unsigned         mmap:1;//Ϊ1ʱ��ʾ��buf�����������������ڴ���, ��ͨ��mmapʹ���ڴ�ӳ����ļ���ӳ�䵽�ڴ��еģ���Щ����ȴ���ܱ����д����filter���б��

    unsigned         recycled:1;//���Ի��յġ�Ҳ�������buf�ǿ��Ա��ͷŵġ�����ֶ�ͨ�������shadow�ֶ�һ��ʹ�õģ�����ʹ��ngx_create_temp_buf ����������buf������������һ��buf��shadow����ô����ʹ������ֶ�����ʾ���buf�ǿ��Ա��ͷŵġ�
    unsigned         in_file:1;//Ϊ1ʱ��ʾ��buf�����������������ļ���
    unsigned         flush:1;//������flush�ֶα�����Ϊ1�ĵ�buf��chain�����chain�����ݼ��㲻�������������ݣ�last_buf�����ã���־����Ҫ��������ݶ����ˣ���Ҳ����������������postpone_output���õ����ƣ����ǻ��ܵ��������ʵ��������������ơ�
    unsigned         sync:1;
    unsigned         last_buf:1;//���ݱ��Զ��chain���ݸ��˹����������ֶ�Ϊ1�����������һ��buf
    unsigned         last_in_chain:1;//�ڵ�ǰ��chain���棬��buf�����һ�����ر�Ҫע�����last_in_chain��buf��һ����last_buf������last_buf��bufһ����last_in_chain�ġ�������Ϊ���ݻᱻ�Զ��chain���ݸ�ĳ��filterģ��

    unsigned         last_shadow:1;//�ڴ���һ��buf��shadow��ʱ��ͨ�����´�����һ��buf��last_shadow��Ϊ1
    unsigned         temp_file:1;//�����ܵ��ڴ�ʹ�õ����ƣ���ʱ��һЩbuf��������Ҫ��д�������ϵ���ʱ�ļ���ȥ����ô��ʱ�������ô˱�־ 

    /* STUB */ int   num;
};


struct ngx_chain_s {
    ngx_buf_t    *buf;
    ngx_chain_t  *next;
};


typedef struct {
    ngx_int_t    num;
    size_t       size;
} ngx_bufs_t;


typedef struct ngx_output_chain_ctx_s  ngx_output_chain_ctx_t;

typedef ngx_int_t (*ngx_output_chain_filter_pt)(void *ctx, ngx_chain_t *in);

typedef void (*ngx_output_chain_aio_pt)(ngx_output_chain_ctx_t *ctx,
    ngx_file_t *file);

struct ngx_output_chain_ctx_s {
    ngx_buf_t                   *buf;				/* ������ʱ��buf */
    ngx_chain_t                 *in;				/* �����˽�Ҫ���͵�chain */
    ngx_chain_t                 *free;				/* �������Ѿ�������ϵ�chain���Ա����ظ����� */
    ngx_chain_t                 *busy;				/* �����˻�δ���͵�chain */

    unsigned                     sendfile:1;		/* sendfile��� */
    unsigned                     directio:1;		/* directio��� */
    unsigned                     unaligned:1;
    unsigned                     need_in_memory:1;	/* �Ƿ���Ҫ���ڴ��б���һ��(ʹ��sendfile�Ļ���
                                                      �ڴ���û���ļ��Ŀ����ģ���������ʱ��Ҫ�����ļ���
                                                      ��ʱ����Ҫ����������) */
    unsigned                     need_in_temp:1;	/* �Ƿ���Ҫ���ڴ������¸���һ�ݣ�����buf�����ڴ滹���ļ�,
                                                      �����Ļ�������ģ�����ֱ���޸�����ڴ� */
    unsigned                     aio:1;

#if (NGX_HAVE_FILE_AIO || NGX_COMPAT)
    ngx_output_chain_aio_pt      aio_handler;
#if (NGX_HAVE_AIO_SENDFILE || NGX_COMPAT)
    ssize_t                    (*aio_preload)(ngx_buf_t *file);
#endif
#endif

#if (NGX_THREADS || NGX_COMPAT)
    ngx_int_t                  (*thread_handler)(ngx_thread_task_t *task,
                                                 ngx_file_t *file);
    ngx_thread_task_t           *thread_task;
#endif

    off_t                        alignment;

    ngx_pool_t                  *pool;
    ngx_int_t                    allocated;			/* �Ѿ��ֱ��buf���� */
    ngx_bufs_t                   bufs;				/* ��Ӧloc conf�����õ�bufs */
    ngx_buf_tag_t                tag;				/* ģ���ǣ���Ҫ����buf���� */

    ngx_output_chain_filter_pt   output_filter;		/* һ����ngx_http_next_filter,Ҳ���Ǽ�������filter�� */
    void                        *filter_ctx;		/* ��ǰfilter�������ģ�
                                                      ����������upstreamҲ�����output_chain */
};


typedef struct {
    ngx_chain_t                 *out;
    ngx_chain_t                **last;
    ngx_connection_t            *connection;
    ngx_pool_t                  *pool;
    off_t                        limit;
} ngx_chain_writer_ctx_t;


#define NGX_CHAIN_ERROR     (ngx_chain_t *) NGX_ERROR


#define ngx_buf_in_memory(b)        (b->temporary || b->memory || b->mmap)
#define ngx_buf_in_memory_only(b)   (ngx_buf_in_memory(b) && !b->in_file)

#define ngx_buf_special(b)                                                   \
    ((b->flush || b->last_buf || b->sync)                                    \
     && !ngx_buf_in_memory(b) && !b->in_file)

#define ngx_buf_sync_only(b)                                                 \
    (b->sync                                                                 \
     && !ngx_buf_in_memory(b) && !b->in_file && !b->flush && !b->last_buf)

#define ngx_buf_size(b)                                                      \
    (ngx_buf_in_memory(b) ? (off_t) (b->last - b->pos):                      \
                            (b->file_last - b->file_pos))

ngx_buf_t *ngx_create_temp_buf(ngx_pool_t *pool, size_t size);
ngx_chain_t *ngx_create_chain_of_bufs(ngx_pool_t *pool, ngx_bufs_t *bufs);


#define ngx_alloc_buf(pool)  ngx_palloc(pool, sizeof(ngx_buf_t))
#define ngx_calloc_buf(pool) ngx_pcalloc(pool, sizeof(ngx_buf_t))

ngx_chain_t *ngx_alloc_chain_link(ngx_pool_t *pool);
#define ngx_free_chain(pool, cl)                                             \
    cl->next = pool->chain;                                                  \
    pool->chain = cl



ngx_int_t ngx_output_chain(ngx_output_chain_ctx_t *ctx, ngx_chain_t *in);
ngx_int_t ngx_chain_writer(void *ctx, ngx_chain_t *in);

ngx_int_t ngx_chain_add_copy(ngx_pool_t *pool, ngx_chain_t **chain,
    ngx_chain_t *in);
ngx_chain_t *ngx_chain_get_free_buf(ngx_pool_t *p, ngx_chain_t **free);
void ngx_chain_update_chains(ngx_pool_t *p, ngx_chain_t **free,
    ngx_chain_t **busy, ngx_chain_t **out, ngx_buf_tag_t tag);

off_t ngx_chain_coalesce_file(ngx_chain_t **in, off_t limit);

ngx_chain_t *ngx_chain_update_sent(ngx_chain_t *in, off_t sent);

#endif /* _NGX_BUF_H_INCLUDED_ */
