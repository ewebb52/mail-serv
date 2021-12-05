#include <stdio.h>
#include <stdlib.h>
#include "list.h"
#include <string.h>

/* adding a recipient to the list of recipients... */
struct Node *addFront(struct Rcpt *queue, void *data)
{
	struct Node *node = malloc(sizeof(struct Node));

	if (node == NULL) {
		perror("malloc returned NULL");
		return NULL;
	}

	node->data = data;

	if (queue->head == NULL) {
		node->next = NULL;
		queue->head = node;
		(queue->size) += 1;
		return node;
	} else if (queue && data) {
		node->next = queue->head;
		queue->head = node;
		(queue->size) += 1;
		return node;
	} else
		return NULL;
}

void removeAllNodes(struct Rcpt *queue)
{
	struct Node *temp;

	while (queue->size > 0) {
		temp = queue->head;
		queue->head = (queue->head)->next;
		free(temp->data);
		queue->size = (queue->size)-1;
		free(temp);
	}
}

struct Node *addBack(struct Rcpt *list, void *data)
{
    struct Node *node = (struct Node *)malloc(sizeof(struct Node));
    if (node == NULL)
	return NULL;
    node->data = data;
    node->next = NULL;

    if (list->head == NULL) {
	list->head = node;
        (list->size) += 1;
        return node;
    }

    struct Node *end = list->head;
    while (end->next != NULL)
	end = end->next;

    end->next = node;
    return node;
}

void traverseAuto(struct Rcpt *queue)
{
	if (queue->size > 0) {
		struct Node *node = queue->head;

		while (node != NULL) {
			if (node->data)
				printf("%s ", (char *)(node->data));
			node = node->next;
		}
	}
}
