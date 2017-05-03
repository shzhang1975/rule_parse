#ifndef HIMAC_RULE_TABLE_H_
#define HIMAC_RULE_TABLE_H_

#pragma pack(push,1)

#define MAX_RULE_NUM			32			//规则表的最大条目
#define RULE_ITEM_SIZE			8			//一个规则8个整型字

#define E_PORT					1
#define H_PORT					0


#define MAX_FIELD_NAME_SIZE		17

typedef struct SEG_TABLE_
{
	unsigned int	val;
	char			field_name[MAX_FIELD_NAME_SIZE];
}SEG_TABLE,*PSEG_TABLE;

typedef struct CLAUSE_INFO_
{
	unsigned short	val;
	unsigned char	operator;
	unsigned char	field_num;
}CLAUSE_INFO,*PCLAUSE_INFO;

typedef struct RULE_TABLE_
{
//#ifdef BIG_ENDIAN

	CLAUSE_INFO		clause[3];
	unsigned int	val;
	unsigned int	mask;
	unsigned int	layer:2,
					flow_index:6,
					dword_offset:5,
					pri:3,
					instruction:8,
					res1:8;
	unsigned int	exclusiveness:1,
					rule_chain:1,
					and_or:1,
					res2:29;
	unsigned int	res3;

/*
	CLAUSE_INFO		clause[3];
	unsigned int	val;
	unsigned int	mask;
	unsigned int	res1:8,
					instruction:8,
					pri:3,
					dword_offset:5,
					flow_index:6,
					layer:2;
	unsigned int	res2:29,
					and_or:1,
					rule_chain:1,
					exclusiveness:1;
	unsigned int	res3;
*/
}RULE_TABLE,*PRULE_TABLE;

#pragma pack(pop)

void parse_himac_rule_table(char * rule_table,int port);

#endif

