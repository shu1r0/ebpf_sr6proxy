
#include <stdbool.h>
#include <arpa/inet.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in6.h>
#include <linux/seg6.h>
#include <linux/seg6_local.h>
#include <linux/tcp.h>

#include <linux/pkt_cls.h>

#include "bpf_helpers.h"
#include "bpf_proxy_helpers.h"

/**
 * @brief pased packet header struct
 *
 */
struct pkthdr
{
  struct ethhdr *eth;
  struct iphdr *ip;
  struct ipv6hdr *ipv6;
  struct ipv6_sr_hdr *srh;
};

struct bpf_map_def SEC("maps") config_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 32,
    // .map_flags = 0,
};

/**
 * @brief packet counter
 *
 */
struct bpf_map_def SEC("maps") stats_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 32,
    // .map_flags = 0,
};

struct cache_value
{
  struct ipv6hdr ipv6;
  struct ipv6_sr_hdr srh;
};

/**
 * @brief map for cache set by control plane
 *
 */
struct bpf_map_def SEC("maps") static_proxy_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u8),
    .value_size = sizeof(struct cache_value),
    .max_entries = 2,
    // .map_flags = 0,
};

/**
 * @brief map for cache
 *
 */
struct bpf_map_def SEC("maps") dynamic_proxy_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u8),
    .value_size = sizeof(struct cache_value),
    .max_entries = 2,
    // .map_flags = 0,
};

struct forwarding_value
{
  __u32 behavior;
  __u32 oif;
  struct in_addr nexthopv4;
  struct in6_addr nexthopv6;
};

struct bpf_map_def SEC("maps") forwarding_map = {
    .type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = sizeof(struct in6_addr),
    .value_size = sizeof(struct forwarding_value),
    .max_entries = 1024,
};

/**
 * @brief Parse packet
 *
 * @param data
 * @param data_end
 * @return __always_inline struct*
 */
static __always_inline struct pkthdr *parse(void *data, void *data_end)
{
  bpf_debug("parse packet");
  struct pkthdr *pkthdr;

  if (data < data_end)
  {
    // L2
    pkthdr->eth = data;
    if ((void *)pkthdr->eth + sizeof(*pkthdr->eth) > data_end)
    {
      return NULL;
    }

    // L3
    switch (__constant_htons(pkthdr->eth->h_proto))
    {
    case ETH_P_IP:
      pkthdr->ip = data + sizeof(*pkthdr->eth);
      if ((void *)pkthdr->ip + sizeof(*pkthdr->ip) > data_end)
      {
        return NULL;
      }
      break;
    case ETH_P_IPV6:
      pkthdr->ipv6 = data + sizeof(*pkthdr->eth);
      if ((void *)pkthdr->ipv6 + sizeof(*pkthdr->ipv6) > data_end)
      {
        return NULL;
      }

      // IPv6 Ext header
      if (pkthdr->ipv6->nexthdr == IPPROTO_ROUTING)
      {
        pkthdr->srh = data + sizeof(*pkthdr->eth) + sizeof(*pkthdr->ipv6);
        if ((void *)pkthdr->srh + sizeof(*pkthdr->srh) > data_end)
        {
          return NULL;
        }
      }
      break;
    default:
      break;
    }
  }
  else
  {
    return NULL;
  }

  return pkthdr;
}

static __always_inline int srv6_decap(struct pkthdr *hdr, struct __sk_buff *skb, struct ipv6hdr *deleted_ipv6, struct ipv6_sr_hdr *deleted_srh)
{
  // TODO
  // decap
  return TC_ACT_OK;
}

static __always_inline int srv6_encap(struct pkthdr *hdr, struct __sk_buff *skb, struct ipv6hdr *new_ipv6, struct ipv6_sr_hdr *new_srh)
{
  // TODO
  // encap
  void *data_end = (void *)(long)skb->data_end;

  if (hdr->ip)
  {
    // encap
  }
  else if (hdr->ipv6)
  {
    // encap
  }
  return TC_ACT_OK;
}

static __always_inline int rewrite_dst_last_segment(struct pkthdr *hdr)
{
  // TODO
  // copy segmentList[0] dstAddr
  return TC_ACT_OK;
}

/* ---------------------------------------- *
 * Static Proxy
 *   * target service type: SR-unaware
 *   * decap: true
 *   * related behaivor: End.AS
 *   * chache: false
 * ---------------------------------------- */

/**
 * @brief
 *
 * @param hdr
 * @param skb
 * @return __always_inline
 */
static __always_inline int static_proxy_inbound(struct pkthdr *hdr, struct __sk_buff *skb)
{
  // TODO
  return TC_ACT_OK;
}

static __always_inline int static_proxy_outbound(struct pkthdr *hdr, struct __sk_buff *skb)
{
  // TODO
  return TC_ACT_OK;
}

/**
 * @brief remove outer header
 *
 * @param hdr
 * @param skb
 * @return __always_inline
 */
static __always_inline int static_proxy_decap(struct pkthdr *hdr, struct __sk_buff *skb)
{
  bpf_debug("Delete Segment List with header and Cache header");
  void *data_end = (void *)(long)skb->data_end;

  if (hdr->srh)
  {
    // decap
    // cache header and srh
  }
  return TC_ACT_OK;
}

/**
 * @brief restore cache header
 *
 * @param hdr
 * @param skb
 * @return __always_inline
 */
static __always_inline int static_proxy_encap(struct pkthdr *hdr, struct __sk_buff *skb)
{
  bpf_debug("restore header from cache");
  void *data_end = (void *)(long)skb->data_end;

  // TODO
  return TC_ACT_OK;
}

/* ---------------------------------------- *
 * Dynamic Proxy
 *   * target service type: SR-unaware
 *   * decap: true
 *   * related behaivor: End.AD
 *   * chache: true
 * ---------------------------------------- */

/**
 * @brief
 *
 * @param hdr
 * @param skb
 * @return __always_inline
 */
static __always_inline int dynamic_proxy_inbound(struct pkthdr *hdr, struct __sk_buff *skb)
{
  // TODO
  return TC_ACT_OK;
}

/**
 * @brief
 *
 * @param hdr
 * @param skb
 * @return __always_inline
 */
static __always_inline int dynamic_proxy_outbound(struct pkthdr *hdr, struct __sk_buff *skb)
{
  // TODO
  return TC_ACT_OK;
}

static __always_inline int dynamic_proxy_decap(struct pkthdr *hdr, struct __sk_buff *skb)
{
  bpf_debug("Delete Segment List with header and Cache header");
  void *data_end = (void *)(long)skb->data_end;

  if (hdr->srh)
  {
    // TODO
  }
  return TC_ACT_OK;
}

static __always_inline int dynamic_proxy_encap(struct pkthdr *hdr, struct __sk_buff *skb)
{
  bpf_debug("restore header from cache");
  void *data_end = (void *)(long)skb->data_end;
  if (hdr->ip)
  {
    // TODO
  }
  else if (hdr->ipv6)
  {
    // TODO
  }
  return TC_ACT_OK;
}

/* ---------------------------------------- *
 * Masquerading Proxy
 *   * target service type: SR-unaware
 *   * decap: false (only inline SRv6)
 *   * related behaivor: End.AM
 *   * chache: false
 * ---------------------------------------- */

/**
 * @brief
 *
 * @param hdr
 * @param skb
 * @return __always_inline
 */
static __always_inline int masquerading_proxy(struct pkthdr *hdr, struct __sk_buff *skb)
{
  // TODO
  return TC_ACT_OK;
}

/* ---------------------------------------- *
 * Shared Memory Proxy
 *   * target service type: SR-unaware?
 *   * decap: ?
 *   * related behaivor: ?
 *   * chache: ?
 * ---------------------------------------- */

/**
 * @brief
 *
 * @param hdr
 * @param skb
 * @return __always_inline
 */
static __always_inline int shared_memory_proxy(struct pkthdr *hdr, struct __sk_buff *skb)
{
  // TODO
  return TC_ACT_OK;
}

/**
 * @brief Entrypoint for IFACEOUT
 */
SEC("tc/ifaceout")
int ifaceout(struct __sk_buff *skb)
{
  bpf_debug("Ingress: Enter packet");
  void *data_end = (void *)(long)skb->data_end;
  void *data = (void *)(long)skb->data;
  __u64 packet_size = data_end - data;

  struct pkthdr *pkthdr = parse(data, data_end);
  if (pkthdr)
  {
    if (pkthdr->eth && pkthdr->ipv6 && pkthdr->srh)
    {
      // TODO
    }
  }
  else
  {
    bpf_warn("Failed parsing Packet.");
  }
  return TC_ACT_OK;
}

/**
 * @brief Entrypoint for IFACEIN
 */
SEC("tc/ifacein")
int ifacein(struct __sk_buff *skb)
{
  bpf_debug("Engress: Enter packet");
  void *data_end = (void *)(long)skb->data_end;
  void *data = (void *)(long)skb->data;
  __u64 packet_size = data_end - data;

  // TODO

  return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
