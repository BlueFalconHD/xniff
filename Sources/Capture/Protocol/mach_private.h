#include <mach/mach.h>

typedef enum {
	MACH64_MSG_OPTION_NONE                 = 0x0ull,
	/* share lower 32 bits with mach_msg_option_t */
	MACH64_SEND_MSG                        = MACH_SEND_MSG,
	MACH64_RCV_MSG                         = MACH_RCV_MSG,

	MACH64_RCV_LARGE                       = MACH_RCV_LARGE,
	MACH64_RCV_LARGE_IDENTITY              = MACH_RCV_LARGE_IDENTITY,

	MACH64_SEND_TIMEOUT                    = MACH_SEND_TIMEOUT,
	MACH64_SEND_OVERRIDE                   = MACH_SEND_OVERRIDE,
	MACH64_SEND_INTERRUPT                  = MACH_SEND_INTERRUPT,
	MACH64_SEND_NOTIFY                     = MACH_SEND_NOTIFY,
	MACH64_SEND_ALWAYS                     = MACH_SEND_ALWAYS,
	MACH64_SEND_IMPORTANCE                 = MACH_SEND_IMPORTANCE,
	MACH64_SEND_KERNEL                     = MACH_SEND_KERNEL,
	MACH64_SEND_FILTER_NONFATAL            = MACH_SEND_FILTER_NONFATAL,
	MACH64_SEND_TRAILER                    = MACH_SEND_TRAILER,
	MACH64_SEND_NOIMPORTANCE               = MACH_SEND_NOIMPORTANCE,
	MACH64_SEND_NODENAP                    = MACH_SEND_NODENAP,
	MACH64_SEND_SYNC_OVERRIDE              = MACH_SEND_SYNC_OVERRIDE,
	MACH64_SEND_PROPAGATE_QOS              = MACH_SEND_PROPAGATE_QOS,

	MACH64_SEND_SYNC_BOOTSTRAP_CHECKIN     = MACH_SEND_SYNC_BOOTSTRAP_CHECKIN,

	MACH64_RCV_TIMEOUT                     = MACH_RCV_TIMEOUT,

	MACH64_RCV_INTERRUPT                   = MACH_RCV_INTERRUPT,
	MACH64_RCV_VOUCHER                     = MACH_RCV_VOUCHER,

	MACH64_RCV_GUARDED_DESC                = MACH_RCV_GUARDED_DESC,
	MACH64_RCV_SYNC_WAIT                   = MACH_RCV_SYNC_WAIT,
	MACH64_RCV_SYNC_PEEK                   = MACH_RCV_SYNC_PEEK,

	MACH64_MSG_STRICT_REPLY                = MACH_MSG_STRICT_REPLY,
	/* following options are 64 only */

	/* Send and receive message as vectors */
	MACH64_MSG_VECTOR                      = 0x0000000100000000ull,
	/* The message is a kobject call */
	MACH64_SEND_KOBJECT_CALL               = 0x0000000200000000ull,
	/* The message is sent to a message queue */
	MACH64_SEND_MQ_CALL                    = 0x0000000400000000ull,
	/* This message destination is unknown. Used by old simulators only. */
	MACH64_SEND_ANY                        = 0x0000000800000000ull,
	/* This message is a DriverKit call */
	MACH64_SEND_DK_CALL                    = 0x0000001000000000ull,

	MACH64_POLICY_KERNEL_EXTENSION         = 0x0000002000000000ull,
	MACH64_POLICY_FILTER_NON_FATAL         = 0x0000004000000000ull,
	MACH64_POLICY_FILTER_MSG               = 0x0000008000000000ull,
	/*
	 * Policy for the mach_msg2_trap() call
	 * `MACH64_POLICY_MASK` holds an ipc_space_policy_t bitfield, shifted.
	 */
	MACH64_POLICY_DEFAULT                  = 0x0000010000000000ull, /* IPC_SPACE_POLICY_DEFAULT */
	MACH64_POLICY_ENHANCED                 = 0x0000020000000000ull, /* IPC_SPACE_POLICY_ENHANCED */
	MACH64_POLICY_PLATFORM                 = 0x0000040000000000ull, /* IPC_SPACE_POLICY_PLATFORM */
	MACH64_POLICY_KERNEL                   = 0x0000100000000000ull, /* IPC_SPACE_POLICY_KERNEL */

	MACH64_POLICY_SIMULATED                = 0x0000200000000000ull, /* IPC_SPACE_POLICY_SIMULATED */


	MACH64_POLICY_TRANSLATED               = 0x0000000000000000ull, /* IPC_SPACE_POLICY_TRANSLATED */
	MACH64_POLICY_OPTED_OUT                = 0x0000800000000000ull, /* IPC_SPACE_POLICY_OPTED_OUT */

	MACH64_POLICY_ENHANCED_V0              = 0x0001000000000000ull, /* DEPRECATED - includes macos hardened runtime */
	MACH64_POLICY_ENHANCED_V1              = 0x0002000000000000ull, /* ES features exposed to 3P in FY2024 release */
	MACH64_POLICY_ENHANCED_V2              = 0x0004000000000000ull, /* ES features exposed to 3P in FY2025 release */

	MACH64_POLICY_ENHANCED_VERSION_MASK =  (
		MACH64_POLICY_ENHANCED_V0 | /* IPC_SPACE_POLICY_ENHANCED_V0 */
		MACH64_POLICY_ENHANCED_V1 | /* IPC_SPACE_POLICY_ENHANCED_V1 */
		MACH64_POLICY_ENHANCED_V2   /* IPC_SPACE_POLICY_ENHANCED_V2 */
		),

	MACH64_POLICY_MASK                     = (
		MACH64_POLICY_DEFAULT |
		MACH64_POLICY_ENHANCED |
		MACH64_POLICY_PLATFORM |
		MACH64_POLICY_KERNEL |
		MACH64_POLICY_SIMULATED |
		MACH64_POLICY_TRANSLATED |
		MACH64_POLICY_OPTED_OUT),

	/*
	 * If kmsg has auxiliary data, append it immediate after the message
	 * and trailer.
	 *
	 * Must be used in conjunction with MACH64_MSG_VECTOR,
	 * only used by kevent() from the kernel.
	 */
	MACH64_RCV_LINEAR_VECTOR               = 0x1000000000000000ull,
	/* Receive into highest addr of buffer */
	MACH64_RCV_STACK                       = 0x2000000000000000ull,

	/* unused                              = 0x4000000000000000ull, */

	/*
	 * This is a mach_msg2() send/receive operation.
	 */
	MACH64_MACH_MSG2                       = 0x8000000000000000ull
} mach_msg_option64_t;


__enum_decl(mach_msgv_index_t, uint32_t, {
	MACH_MSGV_IDX_MSG = 0,
	MACH_MSGV_IDX_AUX = 1,
});

#define MACH_MSGV_MAX_COUNT (MACH_MSGV_IDX_AUX + 1)
/* at least DISPATCH_MSGV_AUX_MAX_SIZE in libdispatch */
#define LIBSYSCALL_MSGV_AUX_MAX_SIZE 128

typedef struct {
	/* a mach_msg_header_t* or mach_msg_aux_header_t* */
	mach_vm_address_t               msgv_data;
	/* if msgv_rcv_addr is non-zero, use it as rcv address instead */
	mach_vm_address_t               msgv_rcv_addr;
	mach_msg_size_t                 msgv_send_size;
	mach_msg_size_t                 msgv_rcv_size;
} mach_msg_vector_t;

typedef struct {
	mach_msg_size_t                 msgdh_size;
	uint32_t                        msgdh_reserved; /* For future */
} mach_msg_aux_header_t;
