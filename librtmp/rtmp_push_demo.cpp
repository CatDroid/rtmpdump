#include "config.h"

#if(RTMP_STREAM_PUSH)

#include <stdio.h>
#include <stdlib.h>
#include "rtmp_push.h"
#include "rtmp.h"   
#include "rtmp_sys.h"   
#include "amf.h"  
//#include "sps_decode.h"

#ifdef PLATFORM_IOS
#include <memory.h>
#include <string.h>
#endif


#ifdef WIN32     
#include <windows.h>  
#pragma comment(lib,"WS2_32.lib")   
#pragma comment(lib,"winmm.lib")  
#endif 

#define RTMP_HEAD_SIZE   (sizeof(RTMPPacket)+RTMP_MAX_HEADER_SIZE)
#define BUFFER_SIZE 32768
#define GOT_A_NAL_CROSS_BUFFER BUFFER_SIZE+1
#define GOT_A_NAL_INCLUDE_A_BUFFER BUFFER_SIZE+2
#define NO_MORE_BUFFER_TO_READ BUFFER_SIZE+3

typedef struct _NaluUnit {  
	int      type;  
    int      size;  
	uint8_t  *data;  
}NaluUnit;

typedef struct _RTMPMetadata {  
	// video, must be h264 type   
	unsigned int    nWidth;  
	unsigned int    nHeight;  
	unsigned int    nFrameRate;      
	unsigned int    nSpsLen;  
	unsigned char   *Sps;  
	unsigned int    nPpsLen;  
	unsigned char   *Pps;   
} RTMPMetadata,*LPRTMPMetadata;  

enum  
{  
   VIDEO_CODECID_H264 = 7,  
};  

static int socket_ctx_init()    
{    
	#ifdef WIN32     
		WORD version;    
		WSADATA wsaData;    
		version = MAKEWORD(1, 1);    
		return (WSAStartup(version, &wsaData) == 0);    
	#else     
		return TRUE;    
	#endif     
}

static void socket_ctx_uninit()    
{    
	#ifdef WIN32     
	CleanupSockets();   
	WSACleanup();  
	#endif     
}    

typedef struct _RTMPGLOBAL{
	uint8_t          *fname;
	RTMP             *rtmp;  
	RTMPMetadata     metadata;
	uint8_t          *fbuff;
	uint32_t         fbuff_size;
	uint8_t          *fbuff_tmp;
	uint32_t         nalhead_pos;
    struct timeval   prets;
	uint32_t         tick;
	BOOLEAN          aac_conf_send;
}RTMPGLOBAL;

static RTMPGLOBAL rtmp_push={
	/*.fname =*/ NULL,
	/*.rtmp =*/ NULL,
	/*.metadata=*/{0},
	/*.fbuff = */NULL,
	/*.fbuff_size = */BUFFER_SIZE,
	/*.fbuff_tmp = */NULL,
	/*.nalhead_pos = */0,
	/*.prets=*/{0},
	/*.tick=*/ 0,
	/*.aac_conf_send=*/ 0,
};

static int rtmp_push_connect(const char* url)  
{  
    memset(&rtmp_push, 0, sizeof(RTMPGLOBAL));
	
	rtmp_push.nalhead_pos=0;
	rtmp_push.fbuff_size = BUFFER_SIZE;
	rtmp_push.fbuff = (uint8_t*)malloc(BUFFER_SIZE);
	rtmp_push.fbuff_tmp=(uint8_t*)malloc(BUFFER_SIZE);
	
	socket_ctx_init();  
	rtmp_push.rtmp = RTMP_Alloc();
	RTMP_Init(rtmp_push.rtmp);

	if (RTMP_SetupURL(rtmp_push.rtmp,(char*)url) == FALSE){
		RTMP_Free(rtmp_push.rtmp);
		return false;
	}
	RTMP_EnableWrite(rtmp_push.rtmp);
	if (RTMP_Connect(rtmp_push.rtmp, NULL) == FALSE) {
		RTMP_Free(rtmp_push.rtmp);
		return false;
	} 
	if (RTMP_ConnectStream(rtmp_push.rtmp,0) == FALSE){
		RTMP_Close(rtmp_push.rtmp);
		RTMP_Free(rtmp_push.rtmp);
		return false;
	}
	return true;  
}  

static void rtmp_push_close()  
{  
	if(rtmp_push.rtmp)  {  
		RTMP_Close(rtmp_push.rtmp);  
		RTMP_Free(rtmp_push.rtmp);  
		rtmp_push.rtmp = NULL;  
	}  
	socket_ctx_uninit();
	if (rtmp_push.fbuff != NULL){  
		free(rtmp_push.fbuff);
	}  
	if (rtmp_push.fbuff_tmp != NULL){  
		free(rtmp_push.fbuff_tmp);
	}
	if(NULL != rtmp_push.metadata.Pps){
		rtmp_push.metadata.Pps = NULL;
	}
	if(NULL != rtmp_push.metadata.Sps){
		rtmp_push.metadata.Sps = NULL;
	}
} 

int rtmp_send_packet(uint32_t nPacketType,uint8_t *data,uint32_t size,uint32_t nTimestamp)  
{  
	RTMPPacket* packet;
	
	packet = (RTMPPacket *)malloc(RTMP_HEAD_SIZE+size);
	memset(packet,0,RTMP_HEAD_SIZE);
	
	packet->m_body = (char *)packet + RTMP_HEAD_SIZE;
	packet->m_nBodySize = size;
	memcpy(packet->m_body,data,size);
	packet->m_hasAbsTimestamp = 0;
	packet->m_packetType = nPacketType; //audio or video packet type. 
	// packetType 就是Stream Type ID 
	// #define RTMP_PACKET_TYPE_AUDIO              0x08
	// #define RTMP_PACKET_TYPE_VIDEO              0x09
	packet->m_nInfoField2 = rtmp_push.rtmp->m_stream_id;
	packet->m_nChannel = 0x04; // 目前数据通道都是固定的 0x04 命令通道是0x03

	packet->m_headerType = RTMP_PACKET_SIZE_LARGE;
	if (RTMP_PACKET_TYPE_AUDIO == nPacketType && size !=4)
	{
		//packet->m_headerType = RTMP_PACKET_SIZE_MEDIUM;
	}
	packet->m_nTimeStamp = nTimestamp;

	int nRet =0;
	if (RTMP_IsConnected(rtmp_push.rtmp)){
		nRet = RTMP_SendPacket(rtmp_push.rtmp,packet,TRUE);
	}
	
	free(packet);
	return nRet;  
}  

static int rtmp_send_h264_spspps(uint8_t *pps,int pps_len,uint8_t * sps,int sps_len)
{
	RTMPPacket * packet=NULL;
	uint8_t    * body=NULL;
	int i;
	packet = (RTMPPacket *)malloc(RTMP_HEAD_SIZE+1024);
	//RTMPPacket_Reset(packet);//reset packet state.
	memset(packet,0,RTMP_HEAD_SIZE+1024);
	packet->m_body = (char *)packet + RTMP_HEAD_SIZE;
	body = (unsigned char *)packet->m_body;
	i = 0;
	body[i++] = 0x17;
	body[i++] = 0x00;

	body[i++] = 0x00;
	body[i++] = 0x00;
	body[i++] = 0x00;

	/*AVCDecoderConfigurationRecord*/
	body[i++] = 0x01;
	body[i++] = sps[1]; // AVC Profile  
	body[i++] = sps[2]; // profile_compatibility
	body[i++] = sps[3]; // AVC Level 
	body[i++] = 0xff;

	/*sps*/
	body[i++]   = 0xe1;  // 111(reserved 3bit) 00001(5bit sps个数 1个)
	body[i++] = (sps_len >> 8) & 0xff;
	body[i++] = sps_len & 0xff;		// sps size 占两个字节
	memcpy(&body[i],sps,sps_len);
	i +=  sps_len;

	/*pps*/
	body[i++]   = 0x01;  // 000000001 (pps个数 1个)
	body[i++] = (pps_len >> 8) & 0xff;
	body[i++] = (pps_len) & 0xff;	// pps size 占两个字节
	memcpy(&body[i],pps,pps_len);
	i +=  pps_len;

	packet->m_packetType = RTMP_PACKET_TYPE_VIDEO;
	packet->m_nBodySize = i;
	packet->m_nChannel = 0x04;
	packet->m_nTimeStamp = 0;
	packet->m_hasAbsTimestamp = 0;
	packet->m_headerType = RTMP_PACKET_SIZE_MEDIUM;
	packet->m_nInfoField2 = rtmp_push.rtmp->m_stream_id;

	int nRet = RTMP_SendPacket(rtmp_push.rtmp,packet,TRUE);
	free(packet);   
	return nRet;
}

int rtmp_send_h264_packet(uint8_t *data,uint32_t size,int bIsKeyFrame,uint32_t nTimeStamp)  
{  
    int i = 0, ret=0; 
	static int send_spspps_time = 0;
	if(data == NULL && size<11){  
		return false;  
	}  
	uint8_t *body = (uint8_t*)malloc(size+9);  
	memset(body,0,size+9);
	
	if(bIsKeyFrame){  
		body[i++] = 0x17;// 1:Iframe  7:AVC   	FrameType==(H264 I帧?1:2) CodecID==7 
		body[i++] = 0x01;// AVC NALU   			AVCPacketType == 0x01
		body[i++] = 0x00;  
		body[i++] = 0x00;  
		body[i++] = 0x00;// 					CompositionTime此处仍然设置为 0x000000

		// NALU size   
		body[i++] = size>>24 & 0xff;  
		body[i++] = size>>16 & 0xff;  
		body[i++] = size>>8  & 0xff;  
		body[i++] = size     & 0xff;// 			Data == H264 NALU Size + NALU Raw Data。			
		// NALU data   
		memcpy(&body[i],data,size);  
		/*if((send_spspps_time++ % 3600) == 0)*/
		{
		   rtmp_send_h264_spspps(rtmp_push.metadata.Pps,rtmp_push.metadata.nPpsLen,
			   rtmp_push.metadata.Sps,rtmp_push.metadata.nSpsLen);
		}
	}else{  
		body[i++] = 0x27;// 2:Pframe  7:AVC   
		body[i++] = 0x01;// AVC NALU   
		body[i++] = 0x00;  
		body[i++] = 0x00;  
		body[i++] = 0x00;  

		// NALU size   
		body[i++] = size>>24 &0xff;  
		body[i++] = size>>16 &0xff;  
		body[i++] = size>>8 &0xff;  
		body[i++] = size&0xff;
		// NALU data   
		memcpy(&body[i],data,size);  
	}  
	ret = rtmp_send_packet(RTMP_PACKET_TYPE_VIDEO,body,i+size,nTimeStamp);  
	free(body);  
	return (ret);  
} 

static int mfile_read_buffer(uint8_t *buf, int buf_size )
{
    static FILE *fp_send = NULL;
	static uint8_t*back_fname = NULL;
	
	if(NULL == rtmp_push.fname){
		RTMPLIVE_TRACE("%s: fname param NULL error\n", __FUNCTION__);
		return (-1);
	}
	if(NULL == buf || 0 == buf_size){
		RTMPLIVE_TRACE("%s: read buf param NULL error or buf_size is 0 \n", __FUNCTION__);
		return(-1);
	}
	FP_RESET:
	if(NULL == back_fname){
		back_fname = (uint8_t*)malloc(128);
		memset(back_fname, 0, 128);
		memcpy(back_fname, rtmp_push.fname, 
			(strlen((char*)rtmp_push.fname)>128 ? 128:strlen((char*)rtmp_push.fname)));
		if(fp_send){
			fclose(fp_send);
			fp_send = NULL;
		}
		if(NULL == fp_send){
		 fp_send = fopen((const char*)rtmp_push.fname, "rb");
	    }
	}else{
	    if(0 != memcmp((char*)back_fname, rtmp_push.fname, strlen((char*)rtmp_push.fname))){
			free(back_fname);
			back_fname = NULL;
			goto FP_RESET;
	    }
	}
	
	if(!feof(fp_send)){
		int rsize=fread(buf,1,buf_size,fp_send);
		return rsize;
	}else{
	    if(fp_send){
		   fclose(fp_send);
		   fp_send = NULL;
		}
		if(NULL != back_fname){
			free(back_fname);
			back_fname = NULL;
		}
		return -1;
	}
}
static int mfile_read_first_nalu_frame(NaluUnit &nalu,
	int (*read_buffer)( uint8_t *buf, int buf_size)) 
{
	int naltail_pos=rtmp_push.nalhead_pos;
	memset(rtmp_push.fbuff_tmp,0,BUFFER_SIZE);
	while(rtmp_push.nalhead_pos < rtmp_push.fbuff_size){  
		//search for nal header
		if(rtmp_push.fbuff[rtmp_push.nalhead_pos++] == 0x00 && 
			rtmp_push.fbuff[rtmp_push.nalhead_pos++] == 0x00) 
		{
			if(rtmp_push.fbuff[rtmp_push.nalhead_pos++] == 0x01)
				goto gotnal_head;
			else 
			{
				//cuz we have done an i++ before,so we need to roll back now
				rtmp_push.nalhead_pos--;		
				if(rtmp_push.fbuff[rtmp_push.nalhead_pos++] == 0x00 && 
					rtmp_push.fbuff[rtmp_push.nalhead_pos++] == 0x01)
					goto gotnal_head;
				else
					continue;
			}
		}
		else 
			continue;

		//search for nal tail which is also the head of next nal
gotnal_head:
		//normal case:the whole nal is in this m_pFileBuf
		naltail_pos = rtmp_push.nalhead_pos;  
		while (naltail_pos<rtmp_push.fbuff_size){  
			if(rtmp_push.fbuff[naltail_pos++] == 0x00 && 
				rtmp_push.fbuff[naltail_pos++] == 0x00 ){  
				if(rtmp_push.fbuff[naltail_pos++] == 0x01){
					nalu.size = (naltail_pos-3)-rtmp_push.nalhead_pos;
					break;
				}else{
					naltail_pos--;
					if(rtmp_push.fbuff[naltail_pos++] == 0x00 &&
						rtmp_push.fbuff[naltail_pos++] == 0x01)
					{	
						nalu.size = (naltail_pos-4)-rtmp_push.nalhead_pos;
						break;
					}
				}
			}  
		}

		nalu.type = rtmp_push.fbuff[rtmp_push.nalhead_pos]&0x1f; 
		memcpy(rtmp_push.fbuff_tmp,rtmp_push.fbuff+rtmp_push.nalhead_pos,nalu.size);
		nalu.data=rtmp_push.fbuff_tmp;
		rtmp_push.nalhead_pos=naltail_pos;
		return TRUE;   		
	}
    return FALSE;
}


static int mfile_read_one_nalu_frame(NaluUnit &nalu,
	int (*read_buffer)(uint8_t *buf, int buf_size))  
{    
	int naltail_pos = (int)rtmp_push.nalhead_pos;
	int ret;
	int nalustart;
	memset(rtmp_push.fbuff_tmp,0,BUFFER_SIZE);
	nalu.size=0;
	while(1){
		if(rtmp_push.nalhead_pos==NO_MORE_BUFFER_TO_READ){
			return FALSE;
		}
		while(naltail_pos < rtmp_push.fbuff_size){  
			//search for nal tail
			if(rtmp_push.fbuff[naltail_pos++] == 0x00 && 
				rtmp_push.fbuff[naltail_pos++] == 0x00){
				if(rtmp_push.fbuff[naltail_pos++] == 0x01){	
					nalustart=3;
					goto gotnal ;
				}else {
					//cuz we have done an i++ before,so we need to roll back now
					naltail_pos--;		
					if(rtmp_push.fbuff[naltail_pos++] == 0x00 && 
						rtmp_push.fbuff[naltail_pos++] == 0x01)
					{
						nalustart=4;
						goto gotnal;
					}
					else
						continue;
				}
			}else {
				continue;
			}

			gotnal:	
 				/**
				 *special case1:parts of the nal lies in a fbuff and we have to read from buffer 
				 *again to get the rest part of this nal
				 */
				if(rtmp_push.nalhead_pos==GOT_A_NAL_CROSS_BUFFER 
					|| rtmp_push.nalhead_pos==GOT_A_NAL_INCLUDE_A_BUFFER){
					nalu.size = nalu.size+naltail_pos-nalustart;
					if(nalu.size>BUFFER_SIZE){
						uint8_t *tmp=rtmp_push.fbuff_tmp;	//// save pointer in case realloc fails
						if((rtmp_push.fbuff_tmp = (uint8_t*)realloc(rtmp_push.fbuff_tmp,nalu.size)) ==  NULL )
						{
							free(tmp);  // free original block
							return FALSE;
						}
					}
					memcpy(rtmp_push.fbuff_tmp+nalu.size+nalustart-naltail_pos,rtmp_push.fbuff,naltail_pos-nalustart);
					nalu.data=rtmp_push.fbuff_tmp;
					rtmp_push.nalhead_pos=naltail_pos;
					return TRUE;
				}else {  //normal case:the whole nal is in this fbuff.
					nalu.type = rtmp_push.fbuff[rtmp_push.nalhead_pos]&0x1f; 
					nalu.size=naltail_pos-rtmp_push.nalhead_pos-nalustart;
					if(nalu.type==0x06){
						rtmp_push.nalhead_pos=naltail_pos;
						continue;
					}
					memcpy(rtmp_push.fbuff_tmp,rtmp_push.fbuff+rtmp_push.nalhead_pos,nalu.size);
					nalu.data=rtmp_push.fbuff_tmp;
					rtmp_push.nalhead_pos=naltail_pos;
					return TRUE;    
				} 					
		}

		if(naltail_pos>=rtmp_push.fbuff_size && rtmp_push.nalhead_pos!=GOT_A_NAL_CROSS_BUFFER 
			&& rtmp_push.nalhead_pos != GOT_A_NAL_INCLUDE_A_BUFFER){
			nalu.size = BUFFER_SIZE-rtmp_push.nalhead_pos;
			nalu.type = rtmp_push.fbuff[rtmp_push.nalhead_pos]& 0x1f; 
			memcpy(rtmp_push.fbuff_tmp,rtmp_push.fbuff+rtmp_push.nalhead_pos,nalu.size);
			if((ret=read_buffer(rtmp_push.fbuff,rtmp_push.fbuff_size))<BUFFER_SIZE)
			{
				memcpy(rtmp_push.fbuff_tmp+nalu.size,rtmp_push.fbuff,ret);
				nalu.size=nalu.size+ret;
				nalu.data=rtmp_push.fbuff_tmp;
				rtmp_push.nalhead_pos=NO_MORE_BUFFER_TO_READ;
				return FALSE;
			}
			naltail_pos=0;
			rtmp_push.nalhead_pos=GOT_A_NAL_CROSS_BUFFER;
			continue;
		}
		if(rtmp_push.nalhead_pos==GOT_A_NAL_CROSS_BUFFER || rtmp_push.nalhead_pos == GOT_A_NAL_INCLUDE_A_BUFFER){
			nalu.size = BUFFER_SIZE+nalu.size;
			uint8_t * tmp=rtmp_push.fbuff_tmp;	//// save pointer in case realloc fails
			if((rtmp_push.fbuff_tmp = (uint8_t*)realloc(rtmp_push.fbuff_tmp,nalu.size))== NULL)
			{
				free( tmp );  // free original block
				return FALSE;
			}
			memcpy(rtmp_push.fbuff_tmp+nalu.size-BUFFER_SIZE,rtmp_push.fbuff,BUFFER_SIZE);
			if((ret=read_buffer(rtmp_push.fbuff,rtmp_push.fbuff_size))<BUFFER_SIZE){
				memcpy(rtmp_push.fbuff_tmp+nalu.size,rtmp_push.fbuff,ret);
				nalu.size=nalu.size+ret;
				nalu.data=rtmp_push.fbuff_tmp;
				rtmp_push.nalhead_pos=NO_MORE_BUFFER_TO_READ;
				return FALSE;
			}
			naltail_pos=0;
			rtmp_push.nalhead_pos=GOT_A_NAL_INCLUDE_A_BUFFER;
			continue;
		}
	}
	return FALSE;  
} 

static int rtmp_h264_mediafile_push(const char* fname)  
{    
	int ret;
	uint32_t now,last_update;
	  
	memset(&rtmp_push.metadata,0,sizeof(RTMPMetadata));
	memset(rtmp_push.fbuff,0,BUFFER_SIZE);

	if(NULL == fname || 0 ==strlen(fname)){
		return (FALSE);
	}
GET_NEW_MFILE:
	if (NULL == rtmp_push.fname){
		int flen = strlen(fname);
		rtmp_push.fname =(uint8_t*) malloc(flen+1);
		memset(rtmp_push.fname, 0, flen+1);
		memcpy(rtmp_push.fname, fname, flen);
	}else{
	    if (0 != memcmp(rtmp_push.fname, fname, strlen(fname))){
			free(rtmp_push.fname);
			rtmp_push.fname = NULL;
			goto GET_NEW_MFILE;
	    }
	} 
		
	if((ret=mfile_read_buffer(rtmp_push.fbuff,rtmp_push.fbuff_size))<0){
		return FALSE;
	}

	NaluUnit naluUnit;  
	
	mfile_read_first_nalu_frame(naluUnit,mfile_read_buffer);  
	rtmp_push.metadata.nSpsLen = naluUnit.size;  
	rtmp_push.metadata.Sps=NULL;
	rtmp_push.metadata.Sps=(uint8_t*)malloc(naluUnit.size);
	memcpy(rtmp_push.metadata.Sps,naluUnit.data,naluUnit.size);

	mfile_read_one_nalu_frame(naluUnit,mfile_read_buffer);  
	rtmp_push.metadata.nPpsLen = naluUnit.size; 
	rtmp_push.metadata.Pps=NULL;
	rtmp_push.metadata.Pps=(uint8_t*)malloc(naluUnit.size);
	memcpy(rtmp_push.metadata.Pps,naluUnit.data,naluUnit.size);
	
	int width = 0,height = 0, fps=0;  
	//h264_decode_sps(metaData.Sps,metaData.nSpsLen,width,height,fps);  
	//metaData.nWidth = width;  
	//metaData.nHeight = height;  
	if(fps){
		rtmp_push.metadata.nFrameRate = fps; 
	}else{
		rtmp_push.metadata.nFrameRate = 15;
	}

	uint32_t tick = 0;  
	uint32_t tick_gap = 1000/rtmp_push.metadata.nFrameRate; 
	mfile_read_one_nalu_frame(naluUnit,mfile_read_buffer);
	int bKeyframe  = (naluUnit.type == 0x05) ? TRUE : FALSE;
	int tdiff = 0;
	while(rtmp_send_h264_packet(naluUnit.data,naluUnit.size,bKeyframe,tick)) {    
got_sps_pps:
		RTMPLIVE_TRACE("NALU size:%8d\n",naluUnit.size);
		last_update=RTMP_GetTime();
		if(!mfile_read_one_nalu_frame(naluUnit,mfile_read_buffer)){
			RTMPLIVE_TRACE("file send finish end. \n");
			goto end;
		}
		if(naluUnit.type == 0x07 || naluUnit.type == 0x08){
			RTMPLIVE_TRACE("get sps and pps frame.. \n");
			goto got_sps_pps;
		}
		bKeyframe  = (naluUnit.type == 0x05) ? TRUE : FALSE;
		tick +=tick_gap;
		now=RTMP_GetTime();
		tdiff = now-last_update;
		if (tick_gap > tdiff){
			usleep((tick_gap - tdiff)*1000);  
		}
		RTMPLIVE_TRACE("time tramp:%8d %8d\n",tick_gap, tdiff);
		
	}  
	end:
	free(rtmp_push.metadata.Sps);
	free(rtmp_push.metadata.Pps);
	rtmp_push.metadata.Sps = NULL;
	rtmp_push.metadata.Pps = NULL;
	return TRUE;  
}  

static int rtmp_h264_stream_push(uint8_t *buf, int buf_size, struct timeval ts)
{    
	int ret;
	NaluUnit nalu;  
	uint32_t tick_gap = 0;
	static int first_keyframe_flag = 0;
	int bKeyframe = 0;
	
    if(NULL == buf || 0== buf_size){
		RTMPLIVE_TRACE("%s: H264 data param error\n",__FUNCTION__);
		return(-1);
    }
	//construct nalu unit
	nalu.type = (buf[0] & 0x1F);
	nalu.size = buf_size;
	nalu.data = buf;

	if(nalu.type == 0x7 ){
		if(NULL == rtmp_push.metadata.Sps){
			rtmp_push.metadata.nSpsLen = nalu.size;  
		    rtmp_push.metadata.Sps=(uint8_t*)malloc(nalu.size);
		    memcpy(rtmp_push.metadata.Sps,nalu.data,nalu.size);
		}
		//RTMPLIVE_TRACE("%s: H264 sps frame\n",__FUNCTION__);
		return (0);
	} else if(nalu.type == 0x8 ){
	    if(NULL == rtmp_push.metadata.Pps){
		    rtmp_push.metadata.nPpsLen = nalu.size; 
		    rtmp_push.metadata.Pps=(uint8_t*)malloc(nalu.size);
		    memcpy(rtmp_push.metadata.Pps,nalu.data,nalu.size);
	    }
		//RTMPLIVE_TRACE("%s: H264 pps frame\n",__FUNCTION__);
		return(0);
	}

	rtmp_push.metadata.nFrameRate = 15; 
	tick_gap = 1000/rtmp_push.metadata.nFrameRate; 
	bKeyframe  = (nalu.type == 0x05) ? TRUE : FALSE;
	
	 if(first_keyframe_flag == 0){
		if(bKeyframe){
			first_keyframe_flag = 1;
			goto PACKET_PUSH;
		}
		RTMPLIVE_TRACE("%s: first frame is not keyframe and lost\n",__FUNCTION__);
	    return(TRUE);
    }
	 
	if(rtmp_push.prets.tv_sec == 0 && rtmp_push.prets.tv_usec== 0){
		rtmp_push.prets = ts;
		rtmp_push.tick = 0;
		//RTMPLIVE_TRACE("%s: first pre sec:%ld-%ld\n", __FUNCTION__, rtmp_push.prets.tv_sec, rtmp_push.prets.tv_usec);
	}else{
	    rtmp_push.tick += (((ts.tv_sec - rtmp_push.prets.tv_sec) * 1000000 
			+ (ts.tv_usec - rtmp_push.prets.tv_usec))/1000);
		rtmp_push.prets.tv_sec = ts.tv_sec;
		rtmp_push.prets.tv_usec = ts.tv_usec;
		//RTMPLIVE_TRACE("%s: curr sec:%ld-%ld\n", __FUNCTION__, rtmp_push.prets.tv_sec, rtmp_push.prets.tv_usec);
	}
	
	PACKET_PUSH:
	if(rtmp_send_h264_packet(nalu.data,nalu.size,bKeyframe,rtmp_push.tick)) {    
		if(bKeyframe){
			RTMPLIVE_TRACE("keyframe NALU size:%8d tickms=%ld\n", nalu.size, rtmp_push.tick);
		}else{
			RTMPLIVE_TRACE("send NALU size:%8d tickms=%ld\n", nalu.size, rtmp_push.tick);
		}
	}  

	return TRUE;  
}  

static int rtmp_aac_codec_type(uint8_t(&specinfo)[2], int is_metadata)
{
    	//format: aac |sample rate 44khz|sample size 16bit|channel streto
    	//---1010---|-------11------|------1--------|-----1-----|
	specinfo[0] = 0xaf;
	specinfo[1] = (is_metadata? 0: 1);
	return 1;
}

static int rtmp_aac_configure_send()
{    
	uint8_t specinfo[2];
	uint16_t audio_codec_config = 0;
	int i = 0, ret = 0; 
	#define AAC_CODEC_CONFIG_LEN  16
	uint8_t *body = (uint8_t*)malloc(AAC_CODEC_CONFIG_LEN);  
	
	rtmp_aac_codec_type(specinfo, false);
	body[i++] = specinfo[0];
	body[i++] = specinfo[1];

	audio_codec_config |= ((2<<11) & 0xf800);// 2:aac lc(low complexity)
	audio_codec_config |= ((4<<7) & 0x0780); //4:44khz
	audio_codec_config |= ((1<<3) & 0x78);   //2:strereo
	audio_codec_config |= (0 & 0x7);         //padding:000

	body[i++] = (audio_codec_config >> 8 )&0xff;
	body[i++] = audio_codec_config & 0xff;  
	
	ret = rtmp_send_packet(RTMP_PACKET_TYPE_AUDIO, body, i, 0);  
	free(body);  
	return(ret);
}


static int rtmp_aac_stream_push(uint8_t *buf, int buf_size, struct timeval ts)
{    
	uint8_t specinfo[2];
	uint16_t audio_codec_config = 0;
	int i =0, ret = 0, body_size= buf_size+2; 
	uint8_t *body = (uint8_t*)malloc(body_size);  
	
	if(FALSE == rtmp_push.aac_conf_send){
		rtmp_aac_codec_type(specinfo, true);
	}else {
		rtmp_aac_codec_type(specinfo, false);
	}
	body[i++] = specinfo[0];
	body[i++] = specinfo[1];
	//skip aac adts header
	//memcpy(body + i, buf + 7, buf_size - 7);

	memcpy(body+i, buf , buf_size);
	
	if(rtmp_push.prets.tv_sec == 0 && rtmp_push.prets.tv_usec== 0){
		rtmp_push.prets = ts;
		rtmp_push.tick = 0;
	}else{
		uint32_t diff = ((ts.tv_sec - rtmp_push.prets.tv_sec) * 1000000 
		   + (ts.tv_usec - rtmp_push.prets.tv_usec)) / 1000;
	    	rtmp_push.tick += (diff == 0? 1: diff);
		rtmp_push.prets = ts;
	}
	RTMPLIVE_TRACE("%s: Push aac stream: tick=%d \n", __FUNCTION__, rtmp_push.tick);
	
	if(FALSE == rtmp_push.aac_conf_send){
		rtmp_aac_configure_send();
		rtmp_push.aac_conf_send = TRUE;
	}
	ret = rtmp_send_packet(RTMP_PACKET_TYPE_AUDIO, body, body_size, rtmp_push.tick);  
	free(body);  
	return (ret);
}

static RTMPH264PUSHCTX rtmp_h264_push_ctx = {
	rtmp_push_connect,
	rtmp_h264_stream_push,
	rtmp_aac_stream_push,
	rtmp_h264_mediafile_push, 
	rtmp_push_close,
};

void* rtmp_get_h264_push_ctx()
{
    return (void*)(&rtmp_h264_push_ctx);
}
#endif //RTMP_STREAM_PUSH