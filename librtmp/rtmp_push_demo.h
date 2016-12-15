#ifndef __RTMP_PUSH_H__
#define __RTMP_PUSH_H__

#include "config.h"
#include "utils.h"

#ifdef __cplusplus
extern "C" {
#endif

#if(RTMP_STREAM_PUSH)

typedef struct _RTMPH264PUSHCTX{
	int    (*rtmp_push_connect)(const char* url);
	int    (*rtmp_h264_stream_push)(uint8_t* buff, int len, struct timeval ts);
	int    (*rtmp_aac_stream_push)(uint8_t* buff, int len, struct timeval ts);
	int    (*rtmp_h264_mediafile_push)(const char*fname);
	void   (*rtmp_push_close)();
}RTMPH264PUSHCTX;
extern void* rtmp_get_h264_push_ctx();

#endif

#ifdef __cplusplus
}
#endif

#endif

