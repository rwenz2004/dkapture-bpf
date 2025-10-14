// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1

#pragma once

static inline void byte_reverse(void *d, int sz)
{
	char *c = (char *)d;
	for (int i = 0; i < sz / 2; i++)
	{
		char tmp = c[i];
		int j = sz - i - 1;
		c[i] = c[j];
		c[j] = tmp;
	}
}
