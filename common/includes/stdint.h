#ifndef HAJ_STDINT_H
#define HAJ_STDINT_H

/* ---------------- Fixed-width integer types ---------------- */

/* 8-bit signed integer */
typedef signed char			int8_t;
/* 8-bit unsigned integer */
typedef unsigned char		uint8_t;

/* 16-bit signed integer */
typedef short				int16_t;
/* 16-bit unsigned integer */
typedef unsigned short		uint16_t;

/* 32-bit signed integer */
typedef int					int32_t;
/* 32-bit unsigned integer */
typedef unsigned int		uint32_t;

/* 64-bit signed integer */
typedef signed long			int64_t;
/* 64-bit unsigned integer */
typedef unsigned long		uint64_t;

/* ---------------- Pointer-sized integer types ---------------- */

#if defined(__x86_64__) || defined(__aarch64__)
	/* 64-bit signed integer */
	typedef long			intptr_t;
	/* 64-bit unsigned integer */
	typedef unsigned long	uintptr_t;
#elif defined(__i386__) || defined(__arm__)
	/* 32-bit signed integer */
	typedef int				intptr_t;
	/* 32-bit unsigned integer */
	typedef unsigned int	uintptr_t;
#else
	#error "Unsupported architecture"
#endif

/* ---------------- Minimum-width integer types ---------------- */

/* 8-bit signed integer */
typedef int8_t		int_least8_t;
/* 8-bit unsigned integer */
typedef uint8_t		uint_least8_t;

/* 16-bit signed integer */
typedef int16_t		int_least16_t;
/* 16-bit unsigned integer */
typedef uint16_t	uint_least16_t;
/* 32-bit signed integer */
typedef int32_t		int_least32_t;
/* 32-bit unsigned integer */
typedef uint32_t	uint_least32_t;

/* 64-bit signed integer */
typedef int64_t		int_least64_t;
/* 64-bit unsigned integer */
typedef uint64_t	uint_least64_t;

/* ---------------- Fastest minimum-width integer types ---------------- */

/* Fastest signed integer with at least 8 bits */
typedef signed char		int_fast8_t;
/* Fastest unsigned integer with at least 8 bits */
typedef unsigned char	uint_fast8_t;

/* Fastest signed integer with at least 16 bits */
typedef long			int_fast16_t;
/* Fastest unsigned integer with at least 16 bits */
typedef unsigned long	uint_fast16_t;

/* Fastest signed integer with at least 32 bits */
typedef long			int_fast32_t;
/* Fastest unsigned integer with at least 32 bits */
typedef unsigned long	uint_fast32_t;

/* Fastest signed integer with at least 64 bits */
typedef int64_t			int_fast64_t;
/* Fastest unsigned integer with at least 64 bits */
typedef uint64_t		uint_fast64_t;

/* Integer limits */

/* Minimum value for an int8_t */
#define INT8_MIN	(-128)
/* Maximum value for an int8_t */
#define INT8_MAX	127
/* Maximum value for a uint8_t */
#define UINT8_MAX	255

/* Minimum value for an int16_t */
#define INT16_MIN	(-32768)
/* Maximum value for an int16_t */
#define INT16_MAX	32767
/* Maximum value for a uint16_t */
#define UINT16_MAX	65535
/* Minimum value for an int32_t */
#define INT32_MIN	(-2147483647 - 1)
/* Maximum value for an int32_t */
#define INT32_MAX	2147483647
/* Maximum value for a uint32_t */
#define UINT32_MAX	4294967295U

/* Minimum value for an int64_t */
#define INT64_MIN	(-9223372036854775807LL - 1)
/* Maximum value for an int64_t */
#define INT64_MAX	9223372036854775807LL
/* Maximum value for a uint64_t */
#define UINT64_MAX	18446744073709551615ULL

#endif	/* HAJ_STDINT_H */
