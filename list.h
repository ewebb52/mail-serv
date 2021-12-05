#ifndef _LIST_H_
#define _LIST_H_

struct rcpt {
        char *name;
        char *cert;
};

struct Node {
	void *data;
	struct Node *next;
};

struct Rcpt {
	struct Node *head;
	int size;
};

static inline void initRcpt(struct Rcpt *queue)
{
	queue->head = 0;
	queue->size = 0;
}

struct Node *addFront(struct Rcpt *queue, void *data);

void removeAllNodes(struct Rcpt *queue);

void traverseAuto(struct Rcpt *queue);

#endif
