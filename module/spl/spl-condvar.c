/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 *
 * Copyright (C) 2013 Jorgen Lundman <lundman@lundman.net>
 *
 */

#include <sys/condvar.h>
#include <spl-debug.h>
#include <sys/errno.h>
#include <sys/callb.h>


void
spl_cv_init(kcondvar_t *cvp, char *name, kcv_type_t type, void *arg)
{
}

void
spl_cv_destroy(kcondvar_t *cvp)
{
}

void
spl_cv_signal(kcondvar_t *cvp)
{
    wakeup_one((caddr_t)cvp);
}

void
spl_cv_broadcast(kcondvar_t *cvp)
{
    wakeup((caddr_t)cvp);
}


/*
 * Block on the indicated condition variable and
 * release the associated mutex while blocked.
 */
void
spl_cv_wait(kcondvar_t *cvp, kmutex_t *mp, int flags, const char *msg)
{
    if (msg != NULL && msg[0] == '&')
        ++msg;  /* skip over '&' prefixes */

    mp->m_owner = NULL;
    (void) msleep(cvp, (lck_mtx_t *)&mp->m_lock, flags, msg, 0);
    mp->m_owner = current_thread();
}

/*
 * Same as cv_wait except the thread will unblock at 'tim'
 * (an absolute time) if it hasn't already unblocked.
 *
 * Returns the amount of time left from the original 'tim' value
 * when it was unblocked.
 */
int
spl_cv_timedwait(kcondvar_t *cvp, kmutex_t *mp, clock_t tim, int flags,
				 const char *msg)
{
    struct timespec ts;
    int result;

    if (msg != NULL && msg[0] == '&')
        ++msg;  /* skip over '&' prefixes */

    ts.tv_sec = MAX(1, (tim - zfs_lbolt()) / hz);
    ts.tv_nsec = 0;
#if 1
    if (ts.tv_sec < 1)
        ts.tv_nsec = 100;
#endif
    if (ts.tv_sec > 400) {
        printf("cv_timedwait: will wait %lds\n", ts.tv_sec);
		ts.tv_sec = 5;
	}
    mp->m_owner = NULL;
    result = msleep(cvp, (lck_mtx_t *)&mp->m_lock, flags, msg, &ts);
    mp->m_owner = current_thread();

    return (result == EWOULDBLOCK ? -1 : 0);

}


/*
* Compatibility wrapper for the cv_timedwait_hires() Illumos interface.
*/
clock_t
cv_timedwait_hires(kcondvar_t *cvp, kmutex_t *mp, hrtime_t tim,
                 hrtime_t res, int flag)
{
    struct timespec ts;
    int result;

    if (res > 1) {
        /*
         * Align expiration to the specified resolution.
         */
        if (flag & CALLOUT_FLAG_ROUNDUP)
            tim += res - 1;
        tim = (tim / res) * res;
    }

    if (!(flag & CALLOUT_FLAG_ABSOLUTE))
        tim += gethrtime();

    ts.tv_sec = 0;
    ts.tv_nsec = tim * NSEC_PER_USEC;
    if (ts.tv_nsec < 1)
        ts.tv_nsec = 100;

    if (ts.tv_nsec > 400 * NSEC_PER_SEC) {
        printf("cv_timedwait_hires: will wait %llds\n",ts.tv_sec/NSEC_PER_SEC);
		ts.tv_nsec = 5 * NSEC_PER_SEC;
	}

    mp->m_owner = NULL;
    result = msleep(cvp, (lck_mtx_t *)&mp->m_lock, PRIBIO, "cv_timedwait_hires", &ts);
    mp->m_owner = current_thread();

    return (result == EWOULDBLOCK ? -1 : 0);

}
