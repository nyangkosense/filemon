/* See LICENSE file for copyright and license details. */

#define _POSIX_C_SOURCE 200809L

#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "uid.h"

#define HASHSIZE 101

struct uidentry {
	struct uidentry *next;
	uid_t uid;
	char *name;
};

static struct uidentry *hashtab[HASHSIZE];

static unsigned
hash(uid_t uid)
{
	return uid % HASHSIZE;
}


static struct uidentry *
lookup(uid_t uid)
{
	struct uidentry *np;
	
	for (np = hashtab[hash(uid)]; np; np = np->next)
		if (np->uid == uid)
			return np;
	return NULL;
}

static struct uidentry *
install(uid_t uid, const char *name)
{
	struct uidentry *np;
	unsigned hashval;
	
	if ((np = lookup(uid)) == NULL) {
		np = malloc(sizeof(*np));
		if (!np || !(np->name = strdup(name)))
			return NULL;
		np->uid = uid;
		hashval = hash(uid);
		np->next = hashtab[hashval];
		hashtab[hashval] = np;
	}
	return np;
}

void
uidinit(void)
{
	int i;
	
	for (i = 0; i < HASHSIZE; i++)
		hashtab[i] = NULL;
}

const char *
uidname(uid_t uid)
{
	struct uidentry *entry;
	struct passwd *pw;
	
	if ((entry = lookup(uid)))
		return entry->name;
	
	if ((pw = getpwuid(uid))) {
		install(uid, pw->pw_name);
		return lookup(uid)->name;
	}
	
	return "unknown";
}
