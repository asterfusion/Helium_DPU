/* Copyright (c) 2020 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

/*! \file cavium_release.h  
 *  \brief Routine to parse release string.
 */

#ifndef __CAVIUM_RELEASE_H__
#define __CAVIUM_RELEASE_H__

#include "cnnic_version.h"

static inline void
cavium_parse_cvs_string(const char *cvs_name, char *ver_string, int len)
{
	static char version[sizeof(CNNIC_VERSION) + 100],
	    cvs_name_str[sizeof(CNNIC_VERSION) + 100];
	char *ptr;

	/* The compiler starts complaining if cvs_name is used directly about
	   array subscript exceeding boundary (since it doesnt know size of
	   cvs_name??) , so copy locally. */
	cavium_strncpy(cvs_name_str, sizeof(cvs_name_str), cvs_name,
		       sizeof(cvs_name_str) - 1);

	/* Character 7 is a space when there isn't a tag. Use this as a key to
	   return the build date */
	if (strlen(cvs_name_str) < 7 || cvs_name_str[7] == ' ') {
		cavium_snprintf(version, sizeof(version),
				"Development Build %s", __DATE__);
		version[sizeof(version) - 1] = 0;
		cavium_strncpy(ver_string, len - 1, version, len - 1);
                ver_string[len - 1] = 0;
	} else {
		/* Make a static copy of the CVS Name string so we can modify it */
		cavium_strncpy(version, sizeof(version), cvs_name_str,
			       sizeof(version) - 1);
		version[sizeof(version) - 1] = 0;

		/* Make sure there is an ending space in case someone didn't pass us
		   a CVS Name string */
		version[sizeof(version) - 2] = ' ';

		/* Convert all underscores into spaces or dots */
		while ((ptr = cavium_strchr(version, '_')) != NULL) {
			if ((ptr == version) ||	/* Assume an underscore at beginning should be a space */
			    (ptr[-1] < '0') || (ptr[-1] > '9') ||	/* If the character before it isn't a digit */
			    (ptr[1] < '0') || (ptr[1] > '9'))	/* If the character after it isn't a digit */
				*ptr = ' ';
			else
				*ptr = '.';
		}

		/* Skip over the dollar Name: at the front */
		cavium_strncpy(ver_string, len - 1, version, strlen(version));
	}

}

#endif

/* $Id: cavium_release.h 141410 2016-06-30 14:37:41Z mchalla $ */
