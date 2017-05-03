/*
eth.src
eth.dst
eth.type

ip.src
ip.dst
ip.proto

tcp.src_port
tcp.dst_port

vlan.id
vlan.priority

or and

== != > >= < <=

action:
drop
copy
capture
priority xxx
flowctrl xxx

rule id hport add "eth.src == xx:xx:xx:xx:xx:xx || ip.src != a.b.c.d drop"
rule id eport add "vlan.pri > 3 priority 1"
rule id eport add "ip.proto == 0x8 capture"
rule id eport del "ip.proto == 0x8 copy"

*/

#define MAX_RULE_TAB_SIZE								32
#define MAX_KEY_LIST_SIZE								4
#define MAX_KEY_SIZE									16
#define MAX_IDENTIFIER_VAL_SIZE							(MAX_KEY_SIZE * 2)

#define RULE_DOWNSTREAM									1
#define RULE_UPSTREAM									2

#define RULE_ADD										1
#define RULE_DEL										2

#define OP_DROP											0x01
#define OP_PRIORITY										0x02
#define OP_FLOWCTRL										0x03
#define	OP_COPY											0x81
#define OP_CAPTURE										0x82

#define PROTO_SIZE_ETH_DST								6
#define PROTO_SIZE_ETH_SRC								6
#define PROTO_SIZE_ETH_TYPE								2
#define PROTO_SIZE_VLAN_PRIORITY						1
#define PROTO_SIZE_VLAN_ID								1
#define PROTO_SIZE_IPV4_TOS								1
#define PROTO_SIZE_IPV4_PROTO							1
#define PROTO_SIZE_IPV4_SRC								4
#define PROTO_SIZE_IPV4_DST								4
#define PROTO_SIZE_IPV6_TRAFFIC_CLASS					1
#define PROTO_SIZE_IPV6_FLOW_LABEL						3
#define PROTO_SIZE_IPV6_SRC								16
#define PROTO_SIZE_IPV6_DST								16
#define PROTO_SIZE_TCP_SRC_PORT							2
#define PROTO_SIZE_TCP_DST_PORT							2
#define PROTO_SIZE_UDP_SRC_PORT							2
#define PROTO_SIZE_UDP_DST_PORT							2

#define FLOW_KEY_ETH_DST								0x01
#define FLOW_KEY_ETH_SRC								0x02
#define FLOW_KEY_ETH_TYPE								0x03
#define FLOW_KEY_ETH_VLAN_ID							0x04
#define FLOW_KEY_ETH_VLAN_PRIORITY						0x05
#define FLOW_KEY_IPV4_TOS								0x06
#define FLOW_KEY_IPV4_PROTO								0x07
#define FLOW_KEY_IPV4_SRC								0x08
#define FLOW_KEY_IPV4_DST								0x09
#define FLOW_KEY_IPV6_TRAFFIC_CLASS						0x0A
#define FLOW_KEY_IPV6_FLOW_LABEL						0x0B
#define FLOW_KEY_IPV6_SRC								0x0C
#define FLOW_KEY_IPV6_DST								0x0D
#define FLOW_KEY_TCP_SRC_PORT							0x0E
#define FLOW_KEY_TCP_DST_PORT							0x0F
#define FLOW_KEY_UDP_SRC_PORT							0x10
#define FLOW_KEY_UDP_DST_PORT							0x11
//#define CLASSIFICATION_FLOW_KEY_IP_SRC_PORT				0x12
//#define CLASSIFICATION_FLOW_KEY_IP_DST_PORT				0x13

#define OPERAND_EQUAL									(1 << 5)
#define OPERAND_NOT_EQUAL								(1 << 4)
#define OPERAND_LARGE									(1 << 3)
#define OPERAND_SMALL									(1 << 2)
#define OPERAND_LARGE_EQUAL								(1 << 1)
#define OPERAND_SMALL_EQUAL								(1 << 0)

#define ERROR_INVALIDE_DIRECTION						-1
#define ERROR_INVALIDE_OPERATION						-2
#define ERROR_INVALIDE_ACTION							-3
#define ERROR_INVALIDE_OPERAND							-4

typedef struct FLOW_KEY_
{
	char							identifier;
	char							operand;
	char							identifier_val[MAX_KEY_SIZE];
}FLOW_KEY,*PFLOW_KEY;

typedef struct FLOW_
{
	FLOW_KEY						flow_keys[MAX_KEY_LIST_SIZE];
	char							size;
}FLOW,*PFLOW;

typedef struct FLOW_OP_
{
	char							code;		//drop priority etc.
	int								val;	
}FLOW_OP,*PFLOW_OP;

typedef struct RULE_
{
	char							direction;		//DOWNSTREAM OR UPSTREAM
	char							rule_action;	//ADD OR DELETE
	FLOW							flow;
	FLOW_OP							operation;
}RULE,*PRULE;

/*
typedef struct RULE_TAB_
{
	RULE							rule[MAX_RULE_TAB_SIZE];
	int								size;
}RULE_TAB,*PRULE_TAB;
*/

typedef struct IDENTIFIER_CODE_TAB_
{
	char							* identifer;
	int								id;
}IDENTIFIER_CODE_TAB,*PIDENTIFIER_CODE_TAB;

