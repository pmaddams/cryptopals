#include <sys/types.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/dsa.h>

#include "44.h"

static struct entry *
new_entry(char *s_buf, char *r_buf, char *m_buf)
{
	struct entry *entry;
	size_t i;

	if ((entry = malloc(sizeof(*entry))) == NULL ||
	    (entry->m = BN_new()) == NULL ||
	    (entry->sig = DSA_SIG_new()) == NULL)
		goto fail;

	if ((i = strcspn(m_buf, " ")) > strlen(m_buf)-2)
		goto fail;
	m_buf += i+1;

	m_buf[strcspn(m_buf, "\n")] = '\0';
	if (BN_hex2bn(&entry->m, m_buf) == 0)
		goto fail;

	if ((i = strcspn(s_buf, " ")) > strlen(s_buf)-2)
		goto fail;
	s_buf += i+1;

	s_buf[strcspn(s_buf, "\n")] = '\0';
	if (BN_dec2bn(&entry->sig->s, s_buf) == 0)
		goto fail;

	if ((i = strcspn(r_buf, " ")) > strlen(r_buf)-2)
		goto fail;
	r_buf += i+1;

	r_buf[strcspn(r_buf, "\n")] = '\0';
	if (BN_dec2bn(&entry->sig->r, r_buf) == 0)
		goto fail;

	return entry;
fail:
	return NULL;
}

int
load_data(struct data *data, FILE *fp)
{
	char *msg_buf, *s_buf, *r_buf, *m_buf;
	size_t msg_size, s_size, r_size, m_size;
	ssize_t len;
	struct entry *entry, **newp;

	data->entries = NULL;
	data->len = 0;

	msg_buf = s_buf = r_buf = m_buf = NULL;
	msg_size = s_size = r_size = m_size = 0;

	for (;;) {
		if (getline(&msg_buf, &msg_size, fp) == -1 ||
		    getline(&s_buf, &s_size, fp) == -1 ||
		    getline(&r_buf, &r_size, fp) == -1 ||
		    getline(&m_buf, &m_size, fp) == -1)
			break;

		if ((entry = new_entry(s_buf, r_buf, m_buf)) == NULL ||
		    (newp = reallocarray(data->entries, data->len+1, sizeof(*data->entries))) == NULL)
			goto fail;

		data->entries = newp;
		data->entries[data->len++] = entry;
	}

	if (ferror(fp))
		goto fail;

	free(msg_buf);
	free(s_buf);
	free(r_buf);
	free(m_buf);

	return 1;
fail:
	return 0;
}
