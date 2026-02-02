#ifndef HAJ_STDDEF_H
#define HAJ_STDDEF_H

#if defined(__x86_64__) || defined(__aarch64__)
	typedef unsigned long size_t;
#elif defined(__i386__) || defined(__arm__)
	typedef unsigned int size_t;
#else
	#error "Unsupported architecture"
#endif


#ifndef NULL
#define NULL ((void *)0)
#endif

#endif /* HAJ_STDDEF_H */