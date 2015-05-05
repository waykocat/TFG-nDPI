#ifdef linux
#define _GNU_SOURCE
#include <sched.h>
#endif


#include<jni.h>
#include"dpiadapt.h"
#include "nDPIFiles/src/include/ndpi_main.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <search.h>
#include <pcap.h>
#include <signal.h>
#include <pthread.h>
#include "nDPIFiles/config.h"
#include "nDPIFiles/src/include/ndpi_api.h"
#include <sys/socket.h>

NDPI_PROTOCOL_BITMASK all;



struct thread_stats {
  u_int32_t guessed_flow_protocols;
  u_int64_t raw_packet_count;
  u_int64_t ip_packet_count;
  u_int64_t total_wire_bytes, total_ip_bytes, total_discarded_bytes;
  u_int64_t protocol_counter[NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS + 1];
  u_int64_t protocol_counter_bytes[NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS + 1];
  u_int32_t protocol_flows[NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS + 1];
  u_int32_t ndpi_flow_count;
  u_int64_t tcp_count, udp_count;
  u_int64_t mpls_count, pppoe_count, vlan_count, fragmented_count;
  u_int64_t packet_len[6];
  u_int16_t max_packet_len;
};

#define MAX_NDPI_FLOWS 200000000
#define NUM_ROOTS 512

struct thread_stats stats;
static u_int8_t full_http_dissection = 0;
static u_int32_t size_id_struct = 0;
static u_int32_t size_flow_struct = 0;

 typedef struct ndpi_flow {
  u_int32_t lower_ip;
  u_int32_t upper_ip;
  u_int16_t lower_port;
  u_int16_t upper_port;
  u_int8_t detection_completed, protocol;
  u_int16_t vlan_id;
  struct ndpi_flow_struct *ndpi_flow;
  char lower_name[32], upper_name[32];

  u_int64_t last_seen;

  u_int64_t bytes;
  u_int32_t packets;

  // result only, not used for flow identification
  u_int32_t detected_protocol;

  char host_server_name[256];

  struct {
    char client_certificate[48], server_certificate[48];
  } ssl;

  void *src_id, *dst_id;
} ndpi_flow_t;




static struct ndpi_flow *get_ndpi_flow(
				       const u_int8_t version,
				       u_int16_t vlan_id,
				       const struct ndpi_iphdr *iph,
				       u_int16_t ip_offset,
				       u_int16_t ipsize,
				       u_int16_t l4_packet_len,
				       struct ndpi_id_struct **src,
				       struct ndpi_id_struct **dst,
				       u_int8_t *proto,
				       const struct ndpi_ip6_hdr *iph6) {
  u_int32_t idx, l4_offset;
  struct ndpi_tcphdr *tcph = NULL;
  struct ndpi_udphdr *udph = NULL;
  u_int32_t lower_ip;
  u_int32_t upper_ip;
  u_int16_t lower_port;
  u_int16_t upper_port;
  struct ndpi_flow flow;
  void *ret;
  u_int8_t *l3;

  /*
    Note: to keep things simple (ndpiReader is just a demo app)
    we handle IPv6 a-la-IPv4.
  */
  if(version == 4) {
    if(ipsize < 20)
      return NULL;

    if((iph->ihl * 4) > ipsize || ipsize < ntohs(iph->tot_len)
       || (iph->frag_off & htons(0x1FFF)) != 0)
      return NULL;

    l4_offset = iph->ihl * 4;
    l3 = (u_int8_t*)iph;
  } else {
    l4_offset = sizeof(struct ndpi_ip6_hdr);
    l3 = (u_int8_t*)iph6;
  }

  if(l4_packet_len < 64)
    stats.packet_len[0]++;
  else if(l4_packet_len >= 64 && l4_packet_len < 128)
    stats.packet_len[1]++;
  else if(l4_packet_len >= 128 && l4_packet_len < 256)
    stats.packet_len[2]++;
  else if(l4_packet_len >= 256 && l4_packet_len < 1024)
    stats.packet_len[3]++;
  else if(l4_packet_len >= 1024 && l4_packet_len < 1500)
    stats.packet_len[4]++;
  else if(l4_packet_len >= 1500)
    stats.packet_len[5]++;

  if(l4_packet_len > stats.max_packet_len)
    stats.max_packet_len = l4_packet_len;

  if(iph->saddr < iph->daddr) {
    lower_ip = iph->saddr;
    upper_ip = iph->daddr;
  } else {
    lower_ip = iph->daddr;
    upper_ip = iph->saddr;
  }

  *proto = iph->protocol;

  if(iph->protocol == 6 && l4_packet_len >= 20) {
    stats.tcp_count++;

    // tcp
    tcph = (struct ndpi_tcphdr *) ((u_int8_t *) l3 + l4_offset);
    if(iph->saddr < iph->daddr) {
      lower_port = tcph->source;
      upper_port = tcph->dest;
    } else {
      lower_port = tcph->dest;
      upper_port = tcph->source;

      if(iph->saddr == iph->daddr) {
	if(lower_port > upper_port) {
	  u_int16_t p = lower_port;

	  lower_port = upper_port;
	  upper_port = p;
	}
      }
    }
  } else if(iph->protocol == 17 && l4_packet_len >= 8) {
    // udp
    stats.udp_count++;

    udph = (struct ndpi_udphdr *) ((u_int8_t *) l3 + l4_offset);
    if(iph->saddr < iph->daddr) {
      lower_port = udph->source;
      upper_port = udph->dest;
    } else {
      lower_port = udph->dest;
      upper_port = udph->source;
    }
  } else {
    // non tcp/udp protocols
    lower_port = 0;
    upper_port = 0;
  }

  flow.protocol = iph->protocol, flow.vlan_id = vlan_id;
  flow.lower_ip = lower_ip, flow.upper_ip = upper_ip;
  flow.lower_port = lower_port, flow.upper_port = upper_port;

  if(0)
    printf("[NDPI] [%u][%u:%u <-> %u:%u]\n",
	   iph->protocol, lower_ip, ntohs(lower_port), upper_ip, ntohs(upper_port));

  idx = (vlan_id + lower_ip + upper_ip + iph->protocol + lower_port + upper_port) % NUM_ROOTS;
  //ret = ndpi_tfind(&flow, &ndpi_thread_info[thread_id].ndpi_flows_root[idx], node_cmp);

  if(ret == NULL) {
    if(stats.ndpi_flow_count == MAX_NDPI_FLOWS) {
      printf("ERROR: maximum flow count (%u) has been exceeded\n", MAX_NDPI_FLOWS);
      exit(-1);
    } else {
      struct ndpi_flow *newflow = (struct ndpi_flow*)malloc(sizeof(struct ndpi_flow));

      if(newflow == NULL) {
	printf("[NDPI] %s(1): not enough memory\n", __FUNCTION__);
	return(NULL);
      }

      memset(newflow, 0, sizeof(struct ndpi_flow));
      newflow->protocol = iph->protocol, newflow->vlan_id = vlan_id;
      newflow->lower_ip = lower_ip, newflow->upper_ip = upper_ip;
      newflow->lower_port = lower_port, newflow->upper_port = upper_port;

      if(version == 4) {
	inet_ntop(AF_INET, &lower_ip, newflow->lower_name, sizeof(newflow->lower_name));
	inet_ntop(AF_INET, &upper_ip, newflow->upper_name, sizeof(newflow->upper_name));
      } else {
	inet_ntop(AF_INET6, &iph6->ip6_src, newflow->lower_name, sizeof(newflow->lower_name));
	inet_ntop(AF_INET6, &iph6->ip6_dst, newflow->upper_name, sizeof(newflow->upper_name));
      }

      if((newflow->ndpi_flow = malloc_wrapper(size_flow_struct)) == NULL) {
	printf("[NDPI] %s(2): not enough memory\n", __FUNCTION__);
	return(NULL);
      } else
	memset(newflow->ndpi_flow, 0, size_flow_struct);

      if((newflow->src_id = malloc_wrapper(size_id_struct)) == NULL) {
	printf("[NDPI] %s(3): not enough memory\n", __FUNCTION__);
	return(NULL);
      } else
	memset(newflow->src_id, 0, size_id_struct);

      if((newflow->dst_id = malloc_wrapper(size_id_struct)) == NULL) {
	printf("[NDPI] %s(4): not enough memory\n", __FUNCTION__);
	return(NULL);
      } else
	memset(newflow->dst_id, 0, size_id_struct);

      //ndpi_tsearch(newflow, &ndpi_thread_info[thread_id].ndpi_flows_root[idx], node_cmp); /* Add */
      stats.ndpi_flow_count++;

      *src = newflow->src_id, *dst = newflow->dst_id;

      // printFlow(thread_id, newflow);

      return(newflow);
    }
  } else {
    struct ndpi_flow *flow = *(struct ndpi_flow**)ret;

    if(flow->lower_ip == lower_ip && flow->upper_ip == upper_ip
       && flow->lower_port == lower_port && flow->upper_port == upper_port)
      *src = flow->src_id, *dst = flow->dst_id;
    else
      *src = flow->dst_id, *dst = flow->src_id;

    return flow;
  }
}








// ipsize = header->len - ip_offset ; rawsize = header->len
static unsigned int packet_processing(
					  const u_int64_t time,
				      u_int16_t vlan_id,
				      const struct ndpi_iphdr *iph,
				      struct ndpi_ip6_hdr *iph6,
				      u_int16_t ip_offset,
				      u_int16_t ipsize, u_int16_t rawsize) {

  struct ndpi_id_struct *src, *dst;
  struct ndpi_flow *flow;
  struct ndpi_flow_struct *ndpi_flow = NULL;
  u_int32_t protocol = 0;
  u_int8_t proto;

  if(iph)
    flow = get_ndpi_flow(4, vlan_id, iph, ip_offset, ipsize,
			 ntohs(iph->tot_len) - (iph->ihl * 4),
			 &src, &dst, &proto, NULL);
  /*else
    flow = get_ndpi_flow6(thread_id, vlan_id, iph6, ip_offset, &src, &dst, &proto);*/

  if(flow != NULL) {
    stats.ip_packet_count++;
    stats.total_wire_bytes += rawsize + 24 /* CRC etc */, stats.total_ip_bytes += rawsize;
    ndpi_flow = flow->ndpi_flow;
    flow->packets++, flow->bytes += rawsize;
    flow->last_seen = time;
  } else {
    return(0);
  }

  if(flow->detection_completed) return(0);
 u_int64_t ttime = 1;
 /* protocol = (const u_int32_t)ndpi_detection_process_packet(ndpi_thread_info[thread_id].ndpi_struct, ndpi_flow,
							    iph ? (uint8_t *)iph : (uint8_t *)iph6,
							    ipsize, ttime, src, dst);*/

  flow->detected_protocol = protocol;

  if((flow->detected_protocol != NDPI_PROTOCOL_UNKNOWN)
     || ((proto == IPPROTO_UDP) && (flow->packets > 8))
     || ((proto == IPPROTO_TCP) && (flow->packets > 10))) {
    flow->detection_completed = 1;

    snprintf(flow->host_server_name, sizeof(flow->host_server_name), "%s", flow->ndpi_flow->host_server_name);

    if((proto == IPPROTO_TCP) && (flow->detected_protocol != NDPI_PROTOCOL_DNS)) {
      snprintf(flow->ssl.client_certificate, sizeof(flow->ssl.client_certificate), "%s", flow->ndpi_flow->protos.ssl.client_certificate);
      snprintf(flow->ssl.server_certificate, sizeof(flow->ssl.server_certificate), "%s", flow->ndpi_flow->protos.ssl.server_certificate);
    }

    if((
	(flow->detected_protocol == NDPI_PROTOCOL_HTTP)
	|| (flow->detected_protocol == NDPI_SERVICE_FACEBOOK)
	)
       && full_http_dissection) {
      char *method;

     // printf("[URL] %s\n", ndpi_get_http_url(ndpi_thread_info[thread_id].ndpi_struct, ndpi_flow));
    //  printf("[Content-Type] %s\n", ndpi_get_http_content_type(ndpi_thread_info[thread_id].ndpi_struct, ndpi_flow));

      switch(ndpi_get_http_method(ndpi_thread_info[thread_id].ndpi_struct, ndpi_flow)) {
      case HTTP_METHOD_OPTIONS: method = "HTTP_METHOD_OPTIONS"; break;
      case HTTP_METHOD_GET: method = "HTTP_METHOD_GET"; break;
      case HTTP_METHOD_HEAD: method = "HTTP_METHOD_HEAD"; break;
      case HTTP_METHOD_POST: method = "HTTP_METHOD_POST"; break;
      case HTTP_METHOD_PUT: method = "HTTP_METHOD_PUT"; break;
      case HTTP_METHOD_DELETE: method = "HTTP_METHOD_DELETE"; break;
      case HTTP_METHOD_TRACE: method = "HTTP_METHOD_TRACE"; break;
      case HTTP_METHOD_CONNECT: method = "HTTP_METHOD_CONNECT"; break;
      default: method = "HTTP_METHOD_UNKNOWN"; break;
      }

      printf("[Method] %s\n", method);
    }

    free_ndpi_flow(flow);

    if(verbose > 1) {
      if(enable_protocol_guess) {
	if(flow->detected_protocol == 0 /* UNKNOWN */) {
	  protocol = node_guess_undetected_protocol(thread_id, flow);
	}
      }

      printFlow(thread_id, flow);
    }
  }




  return 0;
}



JNIEXPORT jint JNICALL Java_dpiadapt_sendPacket
(JNIEnv *, jobject, jbyteArray header, jint ipoffset, jint ipsize, jint hdrsize)
	{

            const u_int64_t time = 1;
    		u_int16_t vlan_id = 4;
            const struct ndpi_iphdr *iph;
            struct ndpi_ip6_hdr *iph6;
            u_int16_t ip_offset = (u_int16_t)ipoffset;
            u_int16_t ipsized = (u_int16_t)ipsize;
			u_int16_t rawsize = (u_int16_t)hdrsize;


			packet_processing(time, vlan_id, iph, iph6,
					    ip_offset, hdrsize - ip_offset, hdrsize);



	    return 1;
}


