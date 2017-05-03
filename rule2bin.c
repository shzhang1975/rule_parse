#include <string.h>

#include "rule.h"
#include "himac_rule_code.h"
#include "himac_rule_table.h"

int					himac_rule_item[4 * MAX_RULE_TAB_SIZE]	= {0};

HIMAC_RULE_CLAUSE_FIELD_NUM_CODE		himac_clause_filed_num_code_tab[]		= {
	{FLOW_KEY_ETH_DST			,	0,	3},
	{FLOW_KEY_ETH_SRC			,	3,	3},
	{FLOW_KEY_ETH_TYPE			,	7,	1},
	{FLOW_KEY_ETH_VLAN_ID		,	9,	1},
	{FLOW_KEY_ETH_VLAN_PRIORITY	,	6,	1},
	{FLOW_KEY_IPV4_TOS			,	10,	1},
	{FLOW_KEY_IPV4_PROTO		,	15,	1},	
	{FLOW_KEY_IPV4_SRC			,	11,	2},
	{FLOW_KEY_IPV4_DST			,	13,	2},
	{FLOW_KEY_TCP_SRC_PORT		,	17,	1},
	{FLOW_KEY_TCP_DST_PORT		,	18,	1},
	{FLOW_KEY_UDP_SRC_PORT		,	17,	1},
	{FLOW_KEY_UDP_DST_PORT		,	18,	1}

};

int get_himac_rule_filed_num(int flow_character_key,char * field_num,char * field_size)
{
	int				i;
	int				j;
	int				size;

	size	= sizeof(himac_clause_filed_num_code_tab) / sizeof(HIMAC_RULE_CLAUSE_FIELD_NUM_CODE);

	for(i=0;i<size;i++)
	{
		if(flow_character_key == himac_clause_filed_num_code_tab[i].flow_character_id)
		{
			for(j=0;j<himac_clause_filed_num_code_tab[i].flow_character_size;j++)
			{
				*(field_num + j)	= himac_clause_filed_num_code_tab[i].field_num + j;
			}
			*field_size	= himac_clause_filed_num_code_tab[i].flow_character_size;
			break;
		}
	}

	if(i == size)
		return -1;
	else
		return 0;
}

int rule2bin(PRULE prule,int * himac_rule_item)
{
	int							i;
	int							j;
	char						field_num[3];
	char						field_num_size;
	PRULE_TABLE					prule_item;
	int							clause_index	= 0;

	prule_item	= (PRULE_TABLE)himac_rule_item;

	for(i=0;i<prule->flow.size;i++)
	{
		memset(field_num,0,3);
		field_num_size	= 0;

		get_himac_rule_filed_num(prule->flow.flow_keys[i].identifier,field_num,&field_num_size);

		for(j=0;j<field_num_size;j++)
		{
			prule_item->clause[clause_index].field_num	= field_num[j];
			prule_item->clause[clause_index].operator	= prule->flow.flow_keys[i].operand;

			clause_index++;
			if((clause_index % 3) == 0)
			{
				prule_item++;
			}
		}		
	}

	return 0;
}
