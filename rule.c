#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "rule.h"
#include "himac_rule_table.h"

//RULE_TAB			rule_tab			= {{0},0};
static char			* logical_op_tab[]	= {"&&"};
RULE				rule_item			= {0};

IDENTIFIER_CODE_TAB		flow_key_code_tab[]		= {
	{"eth.dst",					FLOW_KEY_ETH_DST			},
	{"eth.src",					FLOW_KEY_ETH_SRC			},
	{"eth.type",				FLOW_KEY_ETH_TYPE			},
	{"vlan.id",					FLOW_KEY_ETH_VLAN_ID		},
	{"vlan.pri",				FLOW_KEY_ETH_VLAN_PRIORITY	},
	{"ipv4.tos",				FLOW_KEY_IPV4_TOS			},
	{"ipv4.proto",				FLOW_KEY_IPV4_PROTO			},	
	{"ipv4.src",				FLOW_KEY_IPV4_SRC			},
	{"ipv4.dst",				FLOW_KEY_IPV4_DST			},
	//{"ipv6.traffic_class",		FLOW_KEY_IPV6_TRAFFIC_CLASS	,	},	
	//{"ipv6.flow_label",			FLOW_KEY_IPV6_FLOW_LABEL	},
	//{"ipv6.src",				FLOW_KEY_IPV6_SRC			},
	//{"ipv6.dst",				FLOW_KEY_IPV6_DST			},
	{"tcp.src_port",			FLOW_KEY_TCP_SRC_PORT		},
	{"tcp.dst_port",			FLOW_KEY_TCP_DST_PORT		},
	{"udp.src_port",			FLOW_KEY_UDP_SRC_PORT		},
	{"udp.dst_port",			FLOW_KEY_UDP_DST_PORT		}

};

IDENTIFIER_CODE_TAB				op_code_tab[]	= {
	{"==",	OPERAND_EQUAL		},
	{"!=",	OPERAND_NOT_EQUAL	},
	{">",	OPERAND_LARGE		},
	{">=",	OPERAND_LARGE_EQUAL	},	
	{"<",	OPERAND_SMALL		},
	{"<=",	OPERAND_SMALL_EQUAL},	
};

IDENTIFIER_CODE_TAB				action_code_tab[] = {
	{"drop",		OP_DROP		},
	{"priority",	OP_PRIORITY	},
	{"flowctrl",	OP_FLOWCTRL	},
	{"copy",		OP_COPY		},
	{"capture",		OP_CAPTURE	}
};

char * match_operand(char * pstr,int * offset,char * pend)
{
	int			size;
	int			i;
	char		* poperand;

	*offset	= -1;
	size	= sizeof(op_code_tab) / sizeof(IDENTIFIER_CODE_TAB);

	for(i=0;i<size;i++)
	{
		if((poperand = strstr(pstr,op_code_tab[i].identifer)) != NULL)
		{
			if(pend == NULL || poperand < pend)
				break;
			else
				continue;
		}
	}

	//pend为空说明已经为最后一个关系表达式
	if(i == size || (pend != NULL && poperand > pend))
		return NULL;
	else
	{
		*offset = i;
		return poperand;
	}
}

char * match_logical_op(char * pstr,int * offset)
{
	char		* pc;
	int			size;
	int			i;
	char		*plogical_op;

	*offset	= -1;
	size	= sizeof(logical_op_tab) / sizeof(char *);

	pc		= pstr;

	for(i=0;i<size;i++)
	{
		if((plogical_op = strstr(pstr,logical_op_tab[i])) != NULL)
			break;
	}
	if(i == size)
		return NULL;
	else
	{
		*offset = i;
		return plogical_op;
	}
}

char * match_action(char * pc,char * action,int * action_val,int * offset)
{
	int				i;
	int				size;	
	char			* paction;
	char			* pparam;
	char			* ptemp;
	
	*offset	= -1;
	size	= sizeof(action_code_tab) / sizeof(IDENTIFIER_CODE_TAB);
	for(i=0;i<size;i++)
	{
		if((paction = strstr(pc,action_code_tab[i].identifer)) != NULL)
			break;
	}
	if(i == size)
		return NULL;

	*offset = i;

	if( strstr(pc,"priority") != NULL || 
		strstr(pc,"flowctrl") != NULL)
	{//with parameter
		char		* pend;

		pparam	= paction;
		while(*pparam != ' ' && *pparam != '\0')
			pparam++;

		if(*pparam == '\0')
			return NULL;

		memcpy(action,paction,pparam-paction);

		*action_val = strtoul(pparam,&pend,0);
		if(*pend != '\0')
			return NULL;
	}
	else
	{
		pparam	= paction;
		while(*pparam != '\0')
			pparam++;

		memcpy(action,paction,pparam-paction);
	}

	ptemp	= paction - 1;
	if(ptemp > pc && *ptemp == ' ')
	{//要求action动作之前至少有一个空格间隔
		*ptemp = 0;
		return pc;
	}
	else
	{
		return NULL;
	}
}

int set_flow_key(PFLOW_KEY pflow_key,char * identifier,char * op,char * identifier_val)
{
	int				size;
	int				i;

	size	= sizeof(flow_key_code_tab) / sizeof(IDENTIFIER_CODE_TAB);

	for(i=0;i<size;i++)
	{
		if(strncmp(flow_key_code_tab[i].identifer,identifier,strlen(flow_key_code_tab[i].identifer)) == 0)
			break;
	}

	if(i == size)
		return -1;
	else
	{
		pflow_key->identifier	= flow_key_code_tab[i].id;		
	}

	size	= sizeof(op_code_tab) / sizeof(IDENTIFIER_CODE_TAB);
	for(i=0;i<size;i++)
	{
		if(strcmp(op_code_tab[i].identifer,op) == 0)
			break;
	}

	if(i == size)
		return -1;
	else
	{
		pflow_key->operand	= op_code_tab[i].id;		
	}

	strcpy(pflow_key->identifier_val,identifier_val);

	return 0;
}

int parse_flow(char * rule_desp,PRULE prule)
{
	char			identifier[MAX_KEY_SIZE];
	char			identifier_val[MAX_IDENTIFIER_VAL_SIZE];
	char			operand[MAX_KEY_SIZE];
	char			logical_op[MAX_KEY_SIZE]	= {0};
	char			action[MAX_KEY_SIZE]		= {0};
	int				action_val					= 0;
	char			* pc;
	char			* pstart;
	int				offset						= -1;
	int				flow_key_idx				= prule->flow.size;

	pc = rule_desp;

	pc = match_action(pc,action,&action_val,&offset);
	if(pc == NULL)
	{		
		return ERROR_INVALIDE_ACTION;
	}

	puts(action);
	printf("action_val: %d\n",action_val);	

	prule->operation.code	= action_code_tab[offset].id;
	prule->operation.val	= action_val;

	while(*pc)
	{
		unsigned int					cnt;

		char							* pbarrier;

		memset(identifier,0,MAX_KEY_SIZE);
		memset(identifier_val,0,MAX_IDENTIFIER_VAL_SIZE);
		memset(operand,0,MAX_KEY_SIZE);

		pbarrier = match_logical_op(pc,&offset);

		//skip space
		while(*pc == ' ')
			pc++;

		pstart	= pc;

		pc	= match_operand(pc,&offset,pbarrier);

		if(pc == NULL)
		{
			printf("Illegal Operation\n");
			return ERROR_INVALIDE_OPERAND;
		}

		cnt	= pc - pstart;
		memcpy(identifier,pstart,cnt);
		puts(identifier);

		while(*pc == ' ')
			pc++;

		pstart	= pc;

		pc	+= strlen(op_code_tab[offset].identifer);

		memcpy(operand,pstart,pc-pstart);
		puts(operand);

		while(*pc == ' ')
			pc++;

		pstart	= pc;
		pc = match_logical_op(pc,&offset);

		if(pc == NULL)
		{//已经找到字符串的末尾
			strcpy(identifier_val,pstart);
			puts(identifier_val);

			if(set_flow_key(&prule->flow.flow_keys[flow_key_idx],identifier,operand,identifier_val) == -1)
			{
				return ERROR_INVALIDE_OPERAND;
			}
			flow_key_idx++;
			break;
		}

		memcpy(identifier_val,pstart,pc-pstart);
		puts(identifier_val);

		while(*pc == ' ')
			pc++;

		pstart	= pc;

		pc	+= strlen(logical_op_tab[offset]);
		if(*pc != '\0')
		{
			memcpy(logical_op,pstart,pc-pstart);
			puts(logical_op);

			if(set_flow_key(&prule->flow.flow_keys[flow_key_idx],identifier,operand,identifier_val) == -1)
				return ERROR_INVALIDE_OPERAND;

			flow_key_idx++;
		}
	}

	prule->flow.size	= flow_key_idx;

	return 0;
}

int parse_rule(int argc,char * argv[],PRULE prule)
{
	char			* pc;

	if(argc != 6)
	{
		printf("rule_parse rule id up/down add \"rule_desp\"\n");
		return -1;
	}

	pc = argv[3];
	_strlwr(pc);

	if(strcmp(pc,"up") == 0)
		prule->direction	= RULE_UPSTREAM;
	else if(strcmp(pc,"down") == 0)
		prule->direction	= RULE_DOWNSTREAM;
	else
		return ERROR_INVALIDE_DIRECTION;

	pc = argv[4];
	_strlwr(pc);

	if(strcmp(pc,"add") == 0)
		prule->rule_action	= RULE_ADD;
	else if(strcmp(pc,"del") == 0)
		prule->rule_action	= RULE_DEL;
	else
		return ERROR_INVALIDE_OPERATION;

	puts(argv[5]);

	pc	= argv[5];
	_strlwr(pc);

	parse_flow(pc,prule);	

	return 0;
}

int main(int argc,char * argv[])
{
	extern int					himac_rule_item[4 * MAX_RULE_TAB_SIZE];
	extern int rule2bin(PRULE prule,int * himac_rule_item);

	parse_rule(argc,argv,&rule_item);
	rule2bin(&rule_item,himac_rule_item);
	return 0;
}
