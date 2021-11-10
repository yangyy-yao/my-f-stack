#ifndef __FSTACK_RSS_H
#define __FSTACK_RSS_H

#ifdef __cplusplus
extern "C" {
#endif

#define PORT(a, b) ((uint16_t)(((a) & 0xff) << 8) | ((b) & 0xff))

void ff_rss_init(void);


#ifdef __cplusplus
}
#endif

#endif /* ifndef __FSTACK_RSS_H */


