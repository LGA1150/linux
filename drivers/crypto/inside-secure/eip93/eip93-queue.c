// SPDX-License-Identifier: GPL-2.0
/* EIP93 software backlog and sleepable, pipelined submission. */

#include <linux/device.h>

#include "eip93-main.h"
#include "eip93-aead.h"
#include "eip93-cipher.h"
#include "eip93-hash.h"

static int eip93_submit(struct crypto_async_request *async)
{
	switch (crypto_tfm_alg_type(async->tfm)) {
	case CRYPTO_ALG_TYPE_SKCIPHER:
		return eip93_skcipher_submit(async);
	case CRYPTO_ALG_TYPE_AEAD:
		return eip93_aead_submit(async);
	case CRYPTO_ALG_TYPE_AHASH:
		return eip93_hash_submit(async);
	}

	return -EINVAL;
}

static void eip93_complete(struct crypto_async_request *async, int err)
{
	/* Match the bottom-half context of hardware completions. */
	local_bh_disable();
	crypto_request_complete(async, err);
	local_bh_enable();
}

static void eip93_work(struct work_struct *work)
{
	struct eip93_device *eip93 = container_of(work, struct eip93_device, work);
	struct crypto_async_request *async, *backlog;
	int err;

	for (;;) {
		scoped_guard(spinlock_bh, &eip93->queue_lock) {
			backlog = crypto_get_backlog(&eip93->queue);
			async = crypto_dequeue_request(&eip93->queue);
		}
		if (!async)
			return;

		if (backlog)
			eip93_complete(backlog, -EINPROGRESS);

		/* Submission sleeps only when IDs or ring slots are exhausted. */
		err = eip93_submit(async);
		if (err != -EINPROGRESS)
			eip93_complete(async, err);
		/* async may already have completed and been freed. */
	}
}

int eip93_enqueue(struct eip93_device *eip93, struct crypto_async_request *async)
{
	int err;

	guard(spinlock_bh)(&eip93->queue_lock);

	if (eip93->stopping)
		return -ESHUTDOWN;

	err = crypto_enqueue_request(&eip93->queue, async);
	if (err == -EINPROGRESS || err == -EBUSY)
		queue_work(eip93->wq, &eip93->work);

	return err;
}

int eip93_queue_init(struct eip93_device *eip93)
{
	spin_lock_init(&eip93->queue_lock);
	crypto_init_queue(&eip93->queue, EIP93_RING_NUM - 1);
	INIT_WORK(&eip93->work, eip93_work);
	eip93->wq = alloc_ordered_workqueue("eip93-%s", WQ_MEM_RECLAIM,
					    dev_name(eip93->dev));
	if (!eip93->wq)
		return -ENOMEM;

	return 0;
}

static bool eip93_idle(struct eip93_device *eip93)
{
	guard(spinlock_bh)(&eip93->ring->idr_lock);

	return idr_is_empty(&eip93->ring->crypto_async_idr);
}

void eip93_queue_exit(struct eip93_device *eip93)
{
	scoped_guard(spinlock_bh, &eip93->queue_lock)
		eip93->stopping = true;
	destroy_workqueue(eip93->wq);
	wait_event(eip93->ring->idle, eip93_idle(eip93));
}
