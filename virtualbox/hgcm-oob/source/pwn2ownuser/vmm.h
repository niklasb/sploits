#pragma once
#include <cstdint>

#define VMMDEV_REQUEST_HEADER_VERSION (0x10001)

#define VINF_HGCM_ASYNC_EXECUTE                     2903
#define VBOX_HGCM_REQ_DONE 1
#define VBOXOSTYPE_Win10_x64 0x3B100

#pragma pack(4) /* force structure dword packing here. */

typedef uint64_t RTGCPHYS64;
typedef uint64_t RTGCPTR64;
typedef uint32_t RTGCPHYS32;
typedef uint32_t RTGCPTR32;

typedef enum VMMDevRequestType
{
	VMMDevReq_InvalidRequest = 0,
	VMMDevReq_GetMouseStatus = 1,
	VMMDevReq_SetMouseStatus = 2,
	VMMDevReq_SetPointerShape = 3,
	VMMDevReq_GetHostVersion = 4,
	VMMDevReq_Idle = 5,
	VMMDevReq_GetHostTime = 10,
	VMMDevReq_GetHypervisorInfo = 20,
	VMMDevReq_SetHypervisorInfo = 21,
	VMMDevReq_RegisterPatchMemory = 22, /**< @since version 3.0.6 */
	VMMDevReq_DeregisterPatchMemory = 23, /**< @since version 3.0.6 */
	VMMDevReq_SetPowerStatus = 30,
	VMMDevReq_AcknowledgeEvents = 41,
	VMMDevReq_CtlGuestFilterMask = 42,
	VMMDevReq_ReportGuestInfo = 50,
	VMMDevReq_ReportGuestInfo2 = 58, /**< @since version 3.2.0 */
	VMMDevReq_ReportGuestStatus = 59, /**< @since version 3.2.8 */
	VMMDevReq_ReportGuestUserState = 74, /**< @since version 4.3 */
	VMMDevReq_GetDisplayChangeRequest = 51,
	VMMDevReq_VideoModeSupported = 52,
	VMMDevReq_GetHeightReduction = 53,
	VMMDevReq_GetDisplayChangeRequest2 = 54,
	VMMDevReq_ReportGuestCapabilities = 55,
	VMMDevReq_SetGuestCapabilities = 56,
	VMMDevReq_VideoModeSupported2 = 57, /**< @since version 3.2.0 */
	VMMDevReq_GetDisplayChangeRequestEx = 80, /**< @since version 4.2.4 */
	VMMDevReq_HGCMConnect = 60,
	VMMDevReq_HGCMDisconnect = 61,
	VMMDevReq_HGCMCall32 = 62,
	VMMDevReq_HGCMCall64 = 63,
	VMMDevReq_HGCMCall = 62,
	VMMDevReq_HGCMCancel = 64,
	VMMDevReq_HGCMCancel2 = 65,
	VMMDevReq_VideoAccelEnable = 70,
	VMMDevReq_VideoAccelFlush = 71,
	VMMDevReq_VideoSetVisibleRegion = 72,
	VMMDevReq_GetSeamlessChangeRequest = 73,
	VMMDevReq_QueryCredentials = 100,
	VMMDevReq_ReportCredentialsJudgement = 101,
	VMMDevReq_ReportGuestStats = 110,
	VMMDevReq_GetMemBalloonChangeRequest = 111,
	VMMDevReq_GetStatisticsChangeRequest = 112,
	VMMDevReq_ChangeMemBalloon = 113,
	VMMDevReq_GetVRDPChangeRequest = 150,
	VMMDevReq_LogString = 200,
	VMMDevReq_GetCpuHotPlugRequest = 210,
	VMMDevReq_SetCpuHotPlugStatus = 211,
	VMMDevReq_RegisterSharedModule = 212,
	VMMDevReq_UnregisterSharedModule = 213,
	VMMDevReq_CheckSharedModules = 214,
	VMMDevReq_GetPageSharingStatus = 215,
	VMMDevReq_DebugIsPageShared = 216,
	VMMDevReq_GetSessionId = 217, /**< @since version 3.2.8 */
	VMMDevReq_WriteCoreDump = 218,
	VMMDevReq_GuestHeartbeat = 219,
	VMMDevReq_HeartbeatConfigure = 220,
	VMMDevReq_Alloc = 1337,
	VMMDevReq_Free = 1338,
	VMMDevReq_SizeHack = 0x7fffffff
} VMMDevRequestType;

typedef struct VMMDevRequestHeader
{
	/** IN: Size of the structure in bytes (including body).
	* (VBGLREQHDR uses this for input size and output if reserved1 is zero). */
	uint32_t size;
	/** IN: Version of the structure.  */
	uint32_t version;
	/** IN: Type of the request.
	* @note VBGLREQHDR uses this for optional output size. */
	VMMDevRequestType requestType;
	/** OUT: VBox status code. */
	int32_t  rc;
	/** Reserved field no.1. MBZ.
	* @note VBGLREQHDR uses this for optional output size, however never for a
	*       real VMMDev request, only in the I/O control interface. */
	uint32_t reserved1;
	/** Reserved field no.2. MBZ. */
	uint32_t reserved2;
} VMMDevRequestHeader;

/**
* HGCM request header.
*/
typedef struct VMMDevHGCMRequestHeader
{
	/** Request header. */
	VMMDevRequestHeader header;

	/** HGCM flags. */
	uint32_t fu32Flags;

	/** Result code. */
	int32_t result;
} VMMDevHGCMRequestHeader;


typedef enum
{
	VMMDevHGCMParmType_Invalid = 0,
	VMMDevHGCMParmType_32bit = 1,
	VMMDevHGCMParmType_64bit = 2,
	VMMDevHGCMParmType_PhysAddr = 3,  /**< @deprecated Doesn't work, use PageList. */
	VMMDevHGCMParmType_LinAddr = 4,  /**< In and Out */
	VMMDevHGCMParmType_LinAddr_In = 5,  /**< In  (read;  host<-guest) */
	VMMDevHGCMParmType_LinAddr_Out = 6,  /**< Out (write; host->guest) */
	VMMDevHGCMParmType_LinAddr_Locked = 7,  /**< Locked In and Out */
	VMMDevHGCMParmType_LinAddr_Locked_In = 8,  /**< Locked In  (read;  host<-guest) */
	VMMDevHGCMParmType_LinAddr_Locked_Out = 9,  /**< Locked Out (write; host->guest) */
	VMMDevHGCMParmType_PageList = 10, /**< Physical addresses of locked pages for a buffer. */
	VMMDevHGCMParmType_SizeHack = 0x7fffffff
} HGCMFunctionParameterType;

typedef struct {
	HGCMFunctionParameterType type;
	union {
		uint32_t   value32;
		uint64_t   value64;
		struct {
			uint32_t size;
			union {
				RTGCPHYS32 physAddr;
				RTGCPTR32  linearAddr;
			} u;
		} Pointer;
		struct {
			uint32_t size;   /**< Size of the buffer described by the page list. */
			uint32_t offset; /**< Relative to the request header, valid if size != 0. */
		} PageList;
	} u;
} HGCMFunctionParameter32;

typedef struct {
	HGCMFunctionParameterType type;
	union {
		uint32_t   value32;
		uint64_t   value64;
		struct {
			uint32_t size;

			union
			{
				RTGCPHYS64 physAddr;
				RTGCPTR64  linearAddr;
			} u;
		} Pointer;
		struct {
			uint32_t size;   /**< Size of the buffer described by the page list. */
			uint32_t offset; /**< Relative to the request header, valid if size != 0. */
		} PageList;
	} u;
} HGCMFunctionParameter64;

typedef struct {
	VMMDevHGCMRequestHeader header;
	/** IN: Client identifier. */
	uint32_t u32ClientID;
	/** IN: Service function number. */
	uint32_t u32Function;
	/** IN: Number of parameters. */
	uint32_t cParms;
	/** Parameters follow in form: HGCMFunctionParameter aParms[X]; */
	HGCMFunctionParameter32 params[0];
} VMMDevHGCMCall32;

typedef enum
{
	VMMDevHGCMLoc_Invalid = 0,
	VMMDevHGCMLoc_LocalHost = 1,
	VMMDevHGCMLoc_LocalHost_Existing = 2,
	VMMDevHGCMLoc_SizeHack = 0x7fffffff
} HGCMServiceLocationType;

typedef struct
{
	char achName[128]; /**< This is really szName. */
} HGCMServiceLocationHost;

typedef struct HGCMSERVICELOCATION {
	/** Type of the location. */
	HGCMServiceLocationType type;
	union {
		HGCMServiceLocationHost host;
	} u;
} HGCMServiceLocation;

typedef struct {
	/** HGCM request header. */
	VMMDevHGCMRequestHeader header;
	/** IN: Description of service to connect to. */
	HGCMServiceLocation loc;
	/** OUT: Client identifier assigned by local instance of HGCM. */
	uint32_t u32ClientID;
} VMMDevHGCMConnect;


/**
* HGCM disconnect request structure.
*
* Used by VMMDevReq_HGCMDisconnect.
*/
typedef struct {
	/** HGCM request header. */
	VMMDevHGCMRequestHeader header;
	/** IN: Client identifier. */
	uint32_t u32ClientID;
} VMMDevHGCMDisconnect;

enum eGuestFn
{
	/** Get a guest property */
	GET_PROP = 1,
	/** Set a guest property */
	SET_PROP = 2,
	/** Set just the value of a guest property */
	SET_PROP_VALUE = 3,
	/** Delete a guest property */
	DEL_PROP = 4,
	/** Enumerate guest properties */
	ENUM_PROPS = 5,
	/** Poll for guest notifications */
	GET_NOTIFICATION = 6
};


typedef struct VBoxGuestInfo {
	/** The VMMDev interface version expected by additions.
	* *Deprecated*, do not use anymore! Will be removed. */
	uint32_t interfaceVersion;
	/** Guest OS type. */
	uint32_t osType;
} VBoxGuestInfo;

typedef struct {
	VMMDevRequestHeader header;
	/** Guest information. */
	VBoxGuestInfo guestInfo;
} VMMDevReportGuestInfo;


typedef struct
{
	VMMDevRequestHeader         header;
	uint64_t size;
	uint64_t addr; // out
} VMMDevReqAlloc;

typedef struct
{
	VMMDevRequestHeader         header;
	uint64_t addr;
} VMMDevReqFree;

typedef struct
{
	uint32_t flags;        /**< VBOX_HGCM_F_PARM_*. */
	uint16_t offFirstPage; /**< Offset in the first page where data begins. */
	uint16_t cPages;       /**< Number of pages. */
	RTGCPHYS64 aPages[1];  /**< Page addresses. */
} HGCMPageListInfo;

#define VBOX_HGCM_F_PARM_DIRECTION_TO_HOST   1
#define VBOX_HGCM_F_PARM_DIRECTION_FROM_HOST   2
#define VBOX_HGCM_SVC_PARM_PTR   (3U)

typedef uint64_t                RTGCPHYS;
typedef enum VBOXHGCMCMDTYPE
{
	VBOXHGCMCMDTYPE_LOADSTATE = 0,
	VBOXHGCMCMDTYPE_CONNECT,
	VBOXHGCMCMDTYPE_DISCONNECT,
	VBOXHGCMCMDTYPE_CALL,
	VBOXHGCMCMDTYPE_SizeHack = 0x7fffffff
} VBOXHGCMCMDTYPE;

#pragma pack(8)

/**
* Information about a linear ptr parameter.
*/
typedef struct VBOXHGCMLINPTR
{
	/** Index of the parameter. */
	uint32_t iParm;

	/** Offset in the first physical page of the region. */
	uint32_t offFirstPage;

	/** How many pages. */
	uint32_t cPages;

	/** Pointer to array of the GC physical addresses for these pages.
	* It is assumed that the physical address of the locked resident guest page
	* does not change.
	*/
	RTGCPHYS *paPages;

} VBOXHGCMLINPTR;

typedef struct VBOXHGCMSVCPARM
{
	/** VBOX_HGCM_SVC_PARM_* values. */
	uint32_t type;

	union
	{
		uint32_t uint32;
		uint64_t uint64;
		struct
		{
			uint32_t size;
			void *addr;
		} pointer;
	} u;
} VBOXHGCMSVCPARM;


struct VBOXHGCMCMD
{
	/** Active commands, list is protected by critsectHGCMCmdList. */
	struct VBOXHGCMCMD *pNext;
	struct VBOXHGCMCMD *pPrev;

	/** The type of the command. */
	VBOXHGCMCMDTYPE enmCmdType;

	/** Whether the command was cancelled by the guest. */
	bool fCancelled;

	/** Whether the command is in the active commands list. */
	bool fInList;

	/** GC physical address of the guest request. */
	RTGCPHYS        GCPhys;

	/** Request packet size */
	uint32_t        cbSize;

	/** Pointer to converted host parameters in case of a Call request.
	* Parameters follow this structure in the same memory block.
	*/
	VBOXHGCMSVCPARM *paHostParms;

	/* Number of elements in paHostParms */
	uint32_t cHostParms;

	/** Linear pointer parameters information. */
	int cLinPtrs;

	/** How many pages for all linptrs of this command.
	* Only valid if cLinPtrs > 0. This field simplifies loading of saved state.
	*/
	int cLinPtrPages;

	/** Pointer to descriptions of linear pointers.  */
	VBOXHGCMLINPTR *paLinPtrs;
};
