/*
 * Copyright (c) 2005, 2006, Precise Biometrics AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Precise Biometrics AB nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

/*****************************************************************************
 *
 * Header file for the API exported from pbbase and pbbase2.
 *
 ****************************************************************************/
#ifndef HEADER_PBBASE_H
#define HEADER_PBBASE_H

#include <stdlib.h>
#include <limits.h>

#if !defined(PBBASE_NO_PCSC)
#ifdef __APPLE__
#include <PCSC/winscard.h>
#include <PCSC/wintypes.h>
#else
#include <winscard.h>
#endif
#endif

#ifdef _WIN32
#undef PBCALL
#define PBCALL __cdecl
#else
#undef PBCALL
#define PBCALL
#endif

typedef unsigned int pb_handle_t;
typedef void (PBCALL *pb_image_cb_t)(pb_handle_t, pb_handle_t, void*);
typedef void (PBCALL *pb_pnp_cb_t)(pb_handle_t, int, void*);

struct pb_init_data_v1 {
            pb_pnp_cb_t     pnp_cb;
            void*           pnp_context;
};

/*
 * Precise Biometrics error codes.
 */

/* The function returned without errors. */
#define PB_EOK                0

/* At least one buffer has an incorrect size. */
#define PB_EBUFFER            1

/* The function returned because the caller canceled it. */
#define PB_ECANCEL            2

/* An undefined fatal error has occurred. This error code is used for
 * errors that "cannot happen" and isn't covered by any other error code. */
#define PB_EFATAL             3

/* The BIR is corrupt or not recognized as a BIR of the correct type. */
#define PB_EBIR               4

/* The data passed to the function is not of the correct format. */
#define PB_EDATA              5

/* The reader handle does not represent any connected reader. */
#define PB_EREADER            6

/* The session handle does not represent any open session. */
#define PB_ESESSION           7

/* File error. (e.g. "no such file", etc.) */
#define PB_EFILE              8

/* Cannot allocate enough memory. */
#define PB_EMEMORY            9

/* There is no smart card in the reader. */
#define PB_ESMARTCARD        10

/* The caller requested a version of a structure, interface etc. that is
 * not supported by the implementation. */
#define PB_EVERSION          11

/* A function is called before the interface being initialized. */
#define PB_EINIT             12

/* The requested operation is not supported. */
#define PB_ESUPPORT          13

/* At least one of the parameters is invalid. */
#define PB_EPARAMETER        14

/* The reader is busy (only used by GUI components). */
#define PB_EBUSY             15

/* The operation timed-out before it could finish the operation. */
#define PB_ETIMEOUT          16

/* The attribute is read-only. */
#define PB_EREADONLY         17

/* There is no such attribute for this object type. */
#define PB_EATTRIBUTE        18

/* The operation is not permitted (such as reading verification data out
 * of a secure reader, or trying to read from a token without providing
 * the correct read key.) */
#define PB_EPERMISSION       19

/* The handle passed to the function is not correct. */
#define PB_EHANDLE           20

/* Communication error. */
#define PB_ECOMMUNICATION    21


/* Precise Biometrics True and False. */
#define PB_TRUE   1
#define PB_FALSE  0

/* Enrolment purposes. */
#define PB_PURPOSE_ENROLL_BIOMATCH                   0x00000003
#define PB_PURPOSE_ENROLL_ANSI378                    0x02000006
#define PB_PURPOSE_ENROLL_MOC_PPM7                   0x00018001
#define PB_PURPOSE_ENROLL_MOC_HYBRID                 0x00018002
#define PB_PURPOSE_ENROLL_MOC_HYBRID2                0x00018007

/* Process purposes. */
#define PB_PURPOSE_PROCESS_CLIENTSERVER              0x01000001
#define PB_PURPOSE_PROCESS_ANSI378                   0x01000006

/* Other purposes. */
#define PB_PURPOSE_RAW_IMAGE                         0x02000002
#define PB_PURPOSE_WAIT_FINGER_ABSENT                0x02000004
#define PB_PURPOSE_ENROLL_ANY                        0x02000005

/* PNP Events. */
#define PB_PNP_INSERTED                                       1
#define PB_PNP_REMOVED                                        2

/* Directions. */
#define PB_DIRECTION_NONE                                     0
#define PB_DIRECTION_UP                                       1
#define PB_DIRECTION_DOWN                                     2
#define PB_DIRECTION_LEFT                                     4
#define PB_DIRECTION_UP_LEFT                                  5
#define PB_DIRECTION_DOWN_LEFT                                6
#define PB_DIRECTION_RIGHT                                    8
#define PB_DIRECTION_UP_RIGHT                                 9
#define PB_DIRECTION_DOWN_RIGHT                              10
#define PB_MASK_DIRECTIONS                                   15

/* Finger condition. */
#define PB_CONDITION_UNKNOWN                                  0
#define PB_CONDITION_OK                                       1
#define PB_CONDITION_DRY                                     -1
#define PB_CONDITION_WET                                     -2

/* Timeout constants */
#define PB_TIMEOUT_FOREVER                             UINT_MAX

/* Fingerprint representations. */
#define PB_FPR_DEFAULT                                        0
#define PB_FPR_STYLIZED                                       1
#define PB_FPR_FINGERPRINT                                    2

/* pb_handle_t values. */
#define PB_HANDLE_INVALID                                     0
#define PB_READER_SOFTWARE                                    1
#define PB_READER_ANY                                         2

/* Attributes. */
#define PB_ATTR_PCSC_NAME                            0x00000000
#define PB_ATTR_PRODUCT_NAME                         0x00000001
#define PB_ATTR_IS_EMBEDDED                          0x00000002
#define PB_ATTR_SENSOR_IMPRESSION_TYPE               0x00000004
#define PB_ATTR_DATA_LENGTH                          0x10000001
#define PB_ATTR_USE_LATENT_PROTECTION                0x20000001
#define PB_ATTR_CANCEL                               0x20000002
#define PB_ATTR_NOF_OPEN_HANDLES                     0x20000003
#define PB_ATTR_MAX_NOF_OPEN_HANDLES                 0x20000004

/* The sensor impression type returned by PB_ATTR_SENSOR_IMPRESSION_TYPE. */
#define PB_IMPRESSION_TYPE_PLAIN                              0
#define PB_IMPRESSION_TYPE_SWIPE                              8

/* Security levels. */
#define PB_FAR_100                              (0x7fffffff/100)
#define PB_FAR_1000                            (0x7fffffff/1000)
#define PB_FAR_10000                          (0x7fffffff/10000)
#define PB_FAR_100000                        (0x7fffffff/100000)
#define PB_FAR_1000000                      (0x7fffffff/1000000)

/* Tags. */
#ifndef PB_BIR_TAG_PAYLOAD
#define PB_BIR_TAG_PAYLOAD                                 0xc0
#define PB_BIR_TAG_TEMPLATE                                0xc1
#define PB_BIR_TAG_IMAGE                                   0xc3
#define PB_BIR_TAG_BIOMETRIC_HEADER                        0xc5
#define PB_BIR_TAG_REFERENCE_DATA                          0xc6
#define PB_BIR_TAG_VERIFICATION_DATA                       0xc7
#define PB_BIR_TAG_FINGER_CONTAINER                        0xe3
#define PB_BIR_TAG_BIOMETRIC_SUBTYPE                       0xc2
#endif /* PB_BIR_TAG_PAYLOAD */

/* Image orientation values. */
#ifndef PB_BIR_ORIENTATION_ROT_0
#define PB_BIR_ORIENTATION_ROT_0                              0
#define PB_BIR_ORIENTATION_ROT_90                             1
#define PB_BIR_ORIENTATION_ROT_180                            2
#define PB_BIR_ORIENTATION_ROT_270                            3
#define PB_BIR_ORIENTATION_ROT_0_MIRROR                       4
#define PB_BIR_ORIENTATION_ROT_90_MIRROR                      5
#define PB_BIR_ORIENTATION_ROT_180_MIRROR                     6
#define PB_BIR_ORIENTATION_ROT_270_MIRROR                     7
#endif /* PB_BIR_ORIENTATION_ROT_0 */

/* Finger constants. */
#ifndef PB_BIR_FINGER_LEFT_LITTLE
#define PB_BIR_FINGER_LEFT_LITTLE                            54
#define PB_BIR_FINGER_LEFT_RING                              50
#define PB_BIR_FINGER_LEFT_MIDDLE                            46
#define PB_BIR_FINGER_LEFT_POINTER                           42
#define PB_BIR_FINGER_LEFT_THUMB                             38
#define PB_BIR_FINGER_RIGHT_THUMB                            37
#define PB_BIR_FINGER_RIGHT_POINTER                          41
#define PB_BIR_FINGER_RIGHT_MIDDLE                           45
#define PB_BIR_FINGER_RIGHT_RING                             49
#define PB_BIR_FINGER_RIGHT_LITTLE                           53
#endif /* PB_BIR_FINGER_LEFT_LITTLE */


#ifdef __cplusplus
extern "C" {
#endif


/*
 * General functions.
 */

int PBCALL pb_initialize(
        int                     version,
        void*                   init_data,
        int*                    id);

int PBCALL pb_list_readers(
        pb_handle_t**           readerlist, 
        int*                    numreaders);

int PBCALL pb_open_session(
        pb_handle_t             reader, 
        unsigned int            timeout,
        pb_handle_t*            session);

int PBCALL pb_close_session(
        pb_handle_t*            session);

int PBCALL pb_get_reader_attribute(
        pb_handle_t             reader,
        unsigned int            attribute,
        void*                   value,
        size_t                  size,
        size_t*                 size_returned);

int PBCALL pb_set_reader_attribute(
        pb_handle_t             reader,
        unsigned int            attribute,
        const void*             value,
        size_t                  size);

int PBCALL pb_get_session_attribute(
        pb_handle_t             session,
        unsigned int            attribute,
        void*                   value,
        size_t                  size,
        size_t*                 size_returned);

int PBCALL pb_set_session_attribute(
        pb_handle_t             session,
        unsigned int            attribute,
        const void*             value,
        size_t                  size);

int PBCALL pb_get_bir_attribute(
        pb_handle_t             session,
        pb_handle_t             bir,
        unsigned int            attribute,
        void*                   value,
        size_t                  size,
        size_t*                 size_returned);

int PBCALL pb_set_bir_attribute(
        pb_handle_t             session,
        pb_handle_t             bir,
        unsigned int            attribute,
        const void*             value,
        size_t                  size);

int PBCALL pb_handle_to_bir(
        pb_handle_t             session,
        pb_handle_t             handle,
        void**                  bir,
        size_t*                 len);

int PBCALL pb_bir_to_handle(
        pb_handle_t             session,                          
        const void*             bir,
        size_t                  len,
        pb_handle_t*            handle);

int PBCALL pb_cancel(
        pb_handle_t             session);

int PBCALL pb_free_bir_handle(
        pb_handle_t             session,
        pb_handle_t*            bir);

int PBCALL pb_free(
        void*                   ptr);
 
int PBCALL pb_release(
        int                     id);


/*
 * Feedback functions.
 */

int PBCALL pb_finger_guide(
        pb_handle_t             session,
        pb_handle_t             image,
        unsigned int*           direction,
        unsigned int*           score);

int PBCALL pb_finger_present(
        pb_handle_t             session,
        pb_handle_t             image,
        int*                    present);

int PBCALL pb_finger_quality(
        pb_handle_t             session,
        pb_handle_t             image,
        int*                    quality,
        int*                    finger_condition);

int PBCALL pb_get_image_for_viewing(
        pb_handle_t             session,
        pb_handle_t             src_image,
        int                     dest_x_size,
        int                     dest_y_size,
        int                     dest_x_buf_size,
        int                     representation,
        void*                   dest_image);


/*
 * Biometric functions.
 */

int PBCALL pb_capture_image(
        pb_handle_t             session,
        unsigned int            purpose,
        unsigned int            timeout,
        pb_image_cb_t           callback,
        void*                   context,
        pb_handle_t*            image);

int PBCALL pb_capture_verification_data(
        pb_handle_t             session,
        pb_handle_t             biometric_header,
        unsigned int            timeout,
        pb_image_cb_t           callback,
        void*                   context,
        pb_handle_t*            verification_data);

int PBCALL pb_create_template(
        pb_handle_t             session,
        pb_handle_t             image,
        unsigned int            purpose,
        int*                    quality,
        pb_handle_t*            bir);

int PBCALL pb_create_moc_template(
        pb_handle_t             session,
        pb_handle_t             source_bir,
        unsigned int            purpose,
        int                     far_requested,
        int*                    quality,
        pb_handle_t*            biometric_header,
        pb_handle_t*            reference_data);

int PBCALL pb_create_verification_data(
        pb_handle_t             session,
        pb_handle_t             image,
        pb_handle_t             biometric_header,
        pb_handle_t*            verification_data);

int PBCALL pb_enroll(
        pb_handle_t             session,
        unsigned int            purpose,
        unsigned int            timeout,
        pb_image_cb_t           callback,
        void*                   context,
        int*                    quality,
        pb_handle_t*            image,
        pb_handle_t*            bir);

int PBCALL pb_enroll_moc(
        pb_handle_t             session,
        unsigned int            purpose,
        int                     far_requested,
        unsigned int            timeout,
        pb_image_cb_t           callback,
        void*                   context,
        int*                    quality,
        pb_handle_t*            image,
        pb_handle_t*            biometric_header,
        pb_handle_t*            reference_data);

int PBCALL pb_process(
        pb_handle_t             session,
        pb_handle_t             image,
        unsigned int            purpose,
        int*                    quality,
        void**                  bir,
        size_t*                 bir_size);

int PBCALL pb_validate_moc_template(
        pb_handle_t             session,
        pb_handle_t             image,
        pb_handle_t             biometric_header,
        pb_handle_t             reference_data,
        int*                    quality);

int PBCALL pb_validate_template(
        pb_handle_t             session,
        pb_handle_t             image,
        pb_handle_t             bir,
        int*                    quality);

int PBCALL pb_verify(
        pb_handle_t             session,
        pb_handle_t*            templates,
        int                     ntemplates,
        const int*              far_requested,
        const int*              frr_requested,
        unsigned int            timeout,
        pb_image_cb_t           callback,
        void*                   context,
        int*                    result,
        int*                    far_achieved,
        int*                    frr_achieved,
        int*                    score);

int PBCALL pb_verify_match(
        pb_handle_t             session,
        pb_handle_t             image,
        pb_handle_t*            templates,
        unsigned int            ntemplates,
        const int*              far_requested,
        const int*              frr_requested,
        int*                    match_result,
        int*                    index,
        int*                    far_achieved,
        int*                    frr_achieved,
        int*                    score);


/*
 * Smart card functions.
 */

#if !defined(PBBASE_NO_PCSC)
int PBCALL pb_session_from_scardhandle(
        SCARDHANDLE             hCard,
        unsigned int            timeout,
        pb_handle_t*            session);

int PBCALL pb_write_bir_to_card(
        pb_handle_t             session,
        pb_handle_t             bir,
        size_t                  bir_offset,
        size_t                  sendbuf_offset,
        size_t                  size,
        SCARDHANDLE             hCard,
        LPCSCARD_IO_REQUEST     pioSendPci,
        LPCBYTE                 pbSendBuffer,
        DWORD                   cbSendLength,
        LPSCARD_IO_REQUEST      pioRecvPci,
        LPBYTE                  pbRecvBuffer,
        LPDWORD                 pcbRecvLength);
#endif


#ifdef __cplusplus
}
#endif

#endif /* HEADER_PBBASE_H */
