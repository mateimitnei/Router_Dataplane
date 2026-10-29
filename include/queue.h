#ifndef QUEUE_H
#define QUEUE_H

#include "lib.h"
#include "list.h"

struct queue
{
	list head;
	list tail;
};

typedef struct queue *queue;

// O intrare in coada (contine pachetul si alte date)
struct ip_queue_node
{
	char packet[MAX_PACKET_LEN];
	size_t len;
	uint32_t next_hop;
	size_t interface;
};

/* create an empty queue */
extern queue create_queue(void);

/* insert an element at the end of the queue */
extern void queue_enq(queue q, void *element);

/* delete the front element on the queue and return it */
extern void *queue_deq(queue q);

/* return a true value if and only if the queue is empty */
extern int queue_empty(queue q);

#endif
